/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.coyote.AbstractProcessor;
import org.apache.coyote.AbstractProtocol;
import org.apache.coyote.ActionCode;
import org.apache.coyote.AsyncContextCallback;
import org.apache.coyote.InputBuffer;
import org.apache.coyote.OutputBuffer;
import org.apache.coyote.Request;
import org.apache.coyote.Response;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.buf.Ascii;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.SocketWrapper;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;

public class SpdyCoyoteProcessor extends AbstractProcessor<LightProtocol> 
        implements SpdyChannelProcessor {

    private SpdyFramer spdy;
    private int channelId;
    byte[] requestHead;
    ByteChunk keyBuffer = new ByteChunk();
    boolean error = false;

    SpdyFrame oframe = new SpdyFrame();
    SpdyFrame rframe = new SpdyFrame();

    public SpdyCoyoteProcessor(SpdyFramer spdy, AbstractEndpoint endpoint) {
        super(endpoint);
        this.spdy = spdy;
        
        request.setInputBuffer(new LiteInputBuffer());
        response.setOutputBuffer(new LiteOutputBuffer());
        
    }
    
    class LiteInputBuffer implements InputBuffer {
        @Override
        public int doRead(ByteChunk bchunk, Request request)
                throws IOException {
            // TODO: mutex wait
//            int rd =
//                    httpReq.getBody().read(bchunk.getBytes(),
//                        bchunk.getStart(), bchunk.getBytes().length);
//                if (rd > 0) {
//                    bchunk.setEnd(bchunk.getEnd() + rd);
//                }
//                return rd;
            
            return 0;
        }        
    }
    final class LiteOutputBuffer implements OutputBuffer {
        long byteCount;
        
        @Override
        public int doWrite(org.apache.tomcat.util.buf.ByteChunk chunk,
                Response response) throws IOException {
            if (!response.isCommitted()) {

                // Send the connector a request for commit. The connector should
                // then validate the headers, send them (using sendHeader) and
                // set the filters accordingly.
                response.action(ActionCode.COMMIT, null);

            }
            sendDataFrame(channelId, chunk.getBuffer(), chunk.getStart(),
                    chunk.getLength(), false);
            byteCount += chunk.getLength();
            return chunk.getLength();
        }

        @Override
        public long getBytesWritten() {
            return byteCount;
        }
    }
    
    
    @Override
    public void dataFrame(SpdyFrame currentInFrame) {
    }

    @Override
    public void setChannelId(int chId) {
        this.channelId = chId;
    }

    @Override
    public void request(SpdyFrame frame) throws IOException {
        // We need to make a copy - the frame buffer will be reused. 
        // We use the 'wrap' methods of MimeHeaders - which should be 
        // lighter on mem in some cases.
    
        if (requestHead == null || requestHead.length < frame.size) {
            requestHead = new byte[frame.size];
        }
        System.arraycopy(frame.data, 0, requestHead, 0, frame.size);
            
        // Request received.
        MimeHeaders mimeHeaders = request.getMimeHeaders();

        for (int i = 0; i < frame.nvCount; i++) {
            int nameLen = frame.readShort();
            if (nameLen > frame.remaining()) {
                throw new IOException("Name too long");
            }
        
            keyBuffer.setBytes(requestHead, frame.off, nameLen);
            if (keyBuffer.equals("method")) {
                frame.advance(nameLen);                
                int valueLen = frame.readShort();
                if (valueLen > frame.remaining()) {
                    throw new IOException("Name too long");                
                }
                request.method().setBytes(requestHead, frame.off, valueLen);
                frame.advance(valueLen);
            } else if (keyBuffer.equals("url")) {
                frame.advance(nameLen);                
                int valueLen = frame.readShort();
                if (valueLen > frame.remaining()) {
                    throw new IOException("Name too long");                
                }
                request.requestURI().setBytes(requestHead, frame.off, valueLen);
                System.err.println("URL= " + request.requestURI());
                frame.advance(valueLen);
            } else if (keyBuffer.equals("version")) {
                frame.advance(nameLen);                
                int valueLen = frame.readShort();
                if (valueLen > frame.remaining()) {
                    throw new IOException("Name too long");                
                }
                frame.advance(valueLen);
            } else {
                MessageBytes value = mimeHeaders.addValue(requestHead, 
                        frame.off, nameLen);
                frame.advance(nameLen);
                int valueLen = frame.readShort();
                if (valueLen > frame.remaining()) {
                    throw new IOException("Name too long");                
                }
                value.setBytes(requestHead, frame.off, valueLen);
                frame.advance(valueLen);
            }
        }
        
        // 
        AbstractProtocol proto = (AbstractProtocol) endpoint.getProtocol();
        try {
            proto.getAdapter().service(request, response);
        } catch (InterruptedIOException e) {
            error = true;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            //log.error(sm.getString("ajpprocessor.request.process"), t);
            // 500 - Internal Server Error
            t.printStackTrace();
            response.setStatus(500);
            proto.getAdapter().log(request, response, 0);
            error = true;
        }
        
        // TODO: async, etc ( detached mode - use a special light protocol)
        
        if (!response.isCommitted()) {
            response.action(ActionCode.COMMIT, response);
        }
        response.finish();
        
        // TODO: recycle
    }

    static final byte[] EMPTY=new byte[0];
    // Processor implementation
    
    public synchronized void sendDataFrame(int channelId, byte[] data, 
            int start, int length, boolean close) throws IOException {
        oframe.data = data;
        oframe.size = length;
        oframe.off = start;
        oframe.c = false;
        oframe.streamId = channelId;
        oframe.flags = close ? 1 : 0;
        
        spdy.sendFrame(oframe);
    }

    private void maybeCommit() {
        if (outCommit) {
            return;
        }
        if (!response.isCommitted()) {
            // Validate and write response headers
            try {
                prepareResponse();
            } catch (IOException e) {
                // Set error flag
                error = true;
                return;
            }
        }
    }
    
    boolean outClosed = false;
    boolean outCommit = false;
    
    @Override
    public void action(ActionCode actionCode, Object param) {
        System.err.println(actionCode);

        if (actionCode == ActionCode.COMMIT) {
            maybeCommit();
        } else if (actionCode == ActionCode.CLIENT_FLUSH) {
            maybeCommit();

//            try {
//                flush(true);
//            } catch (IOException e) {
//                // Set error flag
//                error = true;
//            }

        } else if (actionCode == ActionCode.DISABLE_SWALLOW_INPUT) {
            // TODO: Do not swallow request input but
            // make sure we are closing the connection
            error = true;

        } else if (actionCode == ActionCode.CLOSE) {
            if (outClosed) {
                return;
            }
            outClosed = true;
            // Close
            // End the processing of the current request, and stop any further
            // transactions with the client
            maybeCommit();

            try {
                sendDataFrame(channelId, EMPTY, 0, 0, true);
            } catch (IOException e) {
                // Set error flag
                e.printStackTrace();
                error = true;
            }

        } else if (actionCode == ActionCode.REQ_SSL_ATTRIBUTE ) {

//            if (!certificates.isNull()) {
//                ByteChunk certData = certificates.getByteChunk();
//                X509Certificate jsseCerts[] = null;
//                ByteArrayInputStream bais =
//                    new ByteArrayInputStream(certData.getBytes(),
//                            certData.getStart(),
//                            certData.getLength());
//                // Fill the  elements.
//                try {
//                    CertificateFactory cf;
//                    if (clientCertProvider == null) {
//                        cf = CertificateFactory.getInstance("X.509");
//                    } else {
//                        cf = CertificateFactory.getInstance("X.509",
//                                clientCertProvider);
//                    }
//                    while(bais.available() > 0) {
//                        X509Certificate cert = (X509Certificate)
//                        cf.generateCertificate(bais);
//                        if(jsseCerts == null) {
//                            jsseCerts = new X509Certificate[1];
//                            jsseCerts[0] = cert;
//                        } else {
//                            X509Certificate [] temp = new X509Certificate[jsseCerts.length+1];
//                            System.arraycopy(jsseCerts,0,temp,0,jsseCerts.length);
//                            temp[jsseCerts.length] = cert;
//                            jsseCerts = temp;
//                        }
//                    }
//                } catch (java.security.cert.CertificateException e) {
//                    getLog().error(sm.getString("ajpprocessor.certs.fail"), e);
//                    return;
//                } catch (NoSuchProviderException e) {
//                    getLog().error(sm.getString("ajpprocessor.certs.fail"), e);
//                    return;
//                }
//                request.setAttribute(SSLSupport.CERTIFICATE_KEY, jsseCerts);
//            }

        } else if (actionCode == ActionCode.REQ_HOST_ATTRIBUTE) {

            // Get remote host name using a DNS resolution
            if (request.remoteHost().isNull()) {
                try {
                    request.remoteHost().setString(InetAddress.getByName
                            (request.remoteAddr().toString()).getHostName());
                } catch (IOException iex) {
                    // Ignore
                }
            }

        } else if (actionCode == ActionCode.REQ_LOCAL_ADDR_ATTRIBUTE) {

            // Copy from local name for now, which should simply be an address
            request.localAddr().setString(request.localName().toString());

        } else if (actionCode == ActionCode.REQ_SET_BODY_REPLAY) {

            // Set the given bytes as the content
//            ByteChunk bc = (ByteChunk) param;
//            int length = bc.getLength();
//            bodyBytes.setBytes(bc.getBytes(), bc.getStart(), length);
//            request.setContentLength(length);
//            first = false;
//            empty = false;
//            replay = true;

        } else if (actionCode == ActionCode.ASYNC_START) {
            asyncStateMachine.asyncStart((AsyncContextCallback) param);
        } else if (actionCode == ActionCode.ASYNC_DISPATCHED) {
            asyncStateMachine.asyncDispatched();
        } else if (actionCode == ActionCode.ASYNC_TIMEOUT) {
            AtomicBoolean result = (AtomicBoolean) param;
            result.set(asyncStateMachine.asyncTimeout());
        } else if (actionCode == ActionCode.ASYNC_RUN) {
            asyncStateMachine.asyncRun((Runnable) param);
        } else if (actionCode == ActionCode.ASYNC_ERROR) {
            asyncStateMachine.asyncError();
        } else if (actionCode == ActionCode.ASYNC_IS_STARTED) {
            ((AtomicBoolean) param).set(asyncStateMachine.isAsyncStarted());
        } else if (actionCode == ActionCode.ASYNC_IS_DISPATCHING) {
            ((AtomicBoolean) param).set(asyncStateMachine.isAsyncDispatching());
        } else if (actionCode == ActionCode.ASYNC_IS_ASYNC) {
            ((AtomicBoolean) param).set(asyncStateMachine.isAsync());
        } else if (actionCode == ActionCode.ASYNC_IS_TIMINGOUT) {
            ((AtomicBoolean) param).set(asyncStateMachine.isAsyncTimingOut());
        }  else {
            //actionInternal(actionCode, param);
        }
        
    }
    
    private static byte[] STATUS = "status".getBytes();
    private static byte[] VERSION = "version".getBytes();
    private static byte[] HTTP11 = "HTTP/1.1".getBytes();
    private static byte[] OK200 = "200 OK".getBytes();
    
    private void prepareResponse() throws IOException {
        rframe.type = SpdyFrameHandler.TYPE_SYN_REPLY;
        rframe.c = true;
        rframe.flags = 0;
        rframe.streamId = channelId;
        rframe.associated = 0;
        
        MimeHeaders headers = response.getMimeHeaders();
        rframe.append16(headers.size() + 2);
        for (int i = 0; i < headers.size(); i++) {
            MessageBytes mb = headers.getName(i);
            mb.toBytes();
            ByteChunk bc = mb.getByteChunk();
            byte[] bb = bc.getBuffer();
            for (int j = bc.getStart(); j < bc.getEnd(); j++) {
                bb[j] = (byte) Ascii.toLower(bb[j]);
            }
            rframe.appendString(bc.getBuffer(), bc.getStart(),  bc.getLength());
            mb = headers.getValue(i);
            mb.toBytes();
            bc = mb.getByteChunk();
            rframe.appendString(bc.getBuffer(), bc.getStart(),  bc.getLength());
        }
        rframe.appendString(STATUS, 0, STATUS.length);
        
        if (response.getStatus() == 0) {
            rframe.appendString(OK200, 0, OK200.length);            
        } else {
            // TODO: optimize
            String status = response.getStatus() + " " + response.getMessage();
            byte[] statusB = status.getBytes();
            rframe.appendString(statusB, 0, statusB.length);            
        }
        rframe.appendString(VERSION, 0, VERSION.length);
        rframe.appendString(HTTP11, 0, HTTP11.length);
        
        rframe.size = rframe.off;
        rframe.off = 0;
        
        spdy.sendFrame(rframe);
        outCommit = true;
    }

    @Override
    protected boolean isComet() {
        return false;
    }

    @Override
    public SocketState process(SocketWrapper<LightProtocol> socket)
            throws IOException {
        throw new IOException("Unimplemented");
    }

    @Override
    public SocketState event(SocketStatus status) throws IOException {
        System.err.println("EVENT: " + status);
        return null;
    }

    @Override
    public SocketState asyncDispatch(SocketStatus status) {
        System.err.println("ASYNC DISPATCH: " + status);
        return null;
    }

    @Override
    protected boolean isUpgrade() {
        return false;
    }

    @Override
    public SocketState upgradeDispatch() throws IOException {
        return null;
    }

}
