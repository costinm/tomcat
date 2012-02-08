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
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.coyote.AbstractProcessor;
import org.apache.coyote.AbstractProtocol;
import org.apache.coyote.ActionCode;
import org.apache.coyote.AsyncContextCallback;
import org.apache.coyote.InputBuffer;
import org.apache.coyote.OutputBuffer;
import org.apache.coyote.Request;
import org.apache.coyote.RequestInfo;
import org.apache.coyote.Response;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.buf.Ascii;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.HttpMessages;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.LightProcessor;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.SocketWrapper;

/**
 * A spdy stream processed by a tomcat servlet
 * 
 * Based on the AJP processor.
 */
public class SpdyTomcatProcessor extends AbstractProcessor<LightProcessor> 
        implements SpdyStream, Runnable {

    // TODO: handle input
    // TODO: recycle
    // TODO: swallow input ( recycle only after input close )
    // TODO: find a way to inject an OutputBuffer, or interecept close() - 
    // so we can send FIN in the last data packet.
    
    private SpdyFramer spdy;
    private int channelId;
    byte[] requestHead;
    ByteChunk keyBuffer = new ByteChunk();
    boolean error = false;

    SpdyFrame oframe;
    private boolean finished;
    
    static final SpdyFrame END_FRAME = new SpdyFrame();
    BlockingQueue<SpdyFrame> inData = new LinkedBlockingQueue<SpdyFrame>();
    SpdyFrame inFrame = null;

    boolean outClosed = false;
    boolean outCommit = false;
    

    boolean finSent;
    boolean finRcvd;

    public SpdyTomcatProcessor(SpdyFramer spdy, AbstractEndpoint endpoint) {
        super(endpoint);
        
        this.spdy = spdy;
        
        request.setInputBuffer(new LiteInputBuffer());
        response.setOutputBuffer(new LiteOutputBuffer());
        
    }
    
    class LiteInputBuffer implements InputBuffer {
        @Override
        public int doRead(ByteChunk bchunk, Request request)
                throws IOException {
            try {
                if (inFrame == null) {
                    // blocking
                    inFrame = inData.poll(endpoint.getSoTimeout(), 
                            TimeUnit.MILLISECONDS);
                }
                if (inFrame == null) {
                    return -1;
                }
                if (inFrame == END_FRAME) {
                    return -1;
                }


                int rd = Math.min(inFrame.endData, bchunk.getBytes().length);
                System.arraycopy(inFrame.data, inFrame.off, bchunk.getBytes(), 
                        bchunk.getStart(), rd);
                inFrame.advance(rd);
                if (inFrame.off == inFrame.endData) {
                    spdy.getContext().releaseFrame(inFrame);
                }
                bchunk.setEnd(bchunk.getEnd() + rd);
                return rd;
            } catch (InterruptedException e) {
                throw new IOException(e);
            }
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
    public void onDataFrame() {
        SpdyFrame inFrame = spdy.popInFrame();
        inData.add(inFrame);
        if (inFrame.closed()) {
            finRcvd = true;
            inData.add(END_FRAME);
        }
    }

    @Override
    public void onCtlFrame() throws IOException {
        // We need to make a copy - the frame buffer will be reused. 
        // We use the 'wrap' methods of MimeHeaders - which should be 
        // lighter on mem in some cases.
        SpdyFrame frame = spdy.inFrame();
        if (frame.type != SpdyFramer.TYPE_SYN_STREAM) {
            // TODO: handle RST, etc.
            return;
        }
        this.channelId = frame.streamId;
        if (frame.isHalfClose()) {
            finRcvd = true;
            inData.add(END_FRAME);
        }
        RequestInfo rp = request.getRequestProcessor();
        rp.setStage(org.apache.coyote.Constants.STAGE_PREPARE);
        
        if (requestHead == null || requestHead.length < frame.endData) {
            requestHead = new byte[frame.endData];
        }
        System.arraycopy(frame.data, 0, requestHead, 0, frame.endData);
            
        // Request received.
        MimeHeaders mimeHeaders = request.getMimeHeaders();

        for (int i = 0; i < frame.nvCount; i++) {
            int nameLen = frame.read16();
            if (nameLen > frame.remaining()) {
                throw new IOException("Name too long");
            }
        
            keyBuffer.setBytes(requestHead, frame.off, nameLen);
            if (keyBuffer.equals("method")) {
                frame.advance(nameLen);                
                int valueLen = frame.read16();
                if (valueLen > frame.remaining()) {
                    throw new IOException("Name too long");                
                }
                request.method().setBytes(requestHead, frame.off, valueLen);
                frame.advance(valueLen);
            } else if (keyBuffer.equals("url")) {
                frame.advance(nameLen);                
                int valueLen = frame.read16();
                if (valueLen > frame.remaining()) {
                    throw new IOException("Name too long");                
                }
                request.requestURI().setBytes(requestHead, frame.off, valueLen);
                System.err.println("URL= " + request.requestURI());
                frame.advance(valueLen);
            } else if (keyBuffer.equals("version")) {
                frame.advance(nameLen);                
                int valueLen = frame.read16();
                if (valueLen > frame.remaining()) {
                    throw new IOException("Name too long");                
                }
                frame.advance(valueLen);
            } else {
                MessageBytes value = mimeHeaders.addValue(requestHead, 
                        frame.off, nameLen);
                frame.advance(nameLen);
                int valueLen = frame.read16();
                if (valueLen > frame.remaining()) {
                    throw new IOException("Name too long");                
                }
                value.setBytes(requestHead, frame.off, valueLen);
                frame.advance(valueLen);
            }
        }
        
        
        Executor exec = spdy.getContext().getExecutor();
        if (exec != null) {
            exec.execute(this);
        } else {
            run(); // probably slow, but shouldn't happen
        }

    }

    /**
     * Execute the request.
     */
    @Override
    public void run() {
        RequestInfo rp = request.getRequestProcessor();
        // 
        AbstractProtocol proto = (AbstractProtocol) endpoint.getProtocol();
        adapter = proto.getAdapter();
        try {
            rp.setStage(org.apache.coyote.Constants.STAGE_SERVICE);
            adapter.service(request, response);
        } catch (InterruptedIOException e) {
            error = true;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            //log.error(sm.getString("ajpprocessor.request.process"), t);
            // 500 - Internal Server Error
            t.printStackTrace();
            response.setStatus(500);
            adapter.log(request, response, 0);
            error = true;
        }
        
        // TODO: async, etc ( detached mode - use a special light protocol)
   
        // Finish the response if not done yet
        if (!finished) {
            try {
                finish();
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                error = true;
            }
        }

        if (error) {
            response.setStatus(500);
        }
        
        request.updateCounters();
        rp.setStage(org.apache.coyote.Constants.STAGE_KEEPALIVE);
        // TODO: recycle
    }


    private void finish() {
        if (!response.isCommitted()) {
            response.action(ActionCode.COMMIT, response);
        }
        
        if (finished)
            return;

        finished = true;
        
        response.finish();
    }
    

    static final byte[] EMPTY=new byte[0];
    // Processor implementation
    
    public synchronized void sendDataFrame(int channelId, byte[] data, 
            int start, int length, boolean close) throws IOException {
        SpdyFrame oframe = spdy.getDataFrame();
        // Sadly, we have to copy the data - the oframe may be queued, and
        // coyote is reusing the buffer.
        oframe.streamId = channelId;
        oframe.flags = close ? 1 : 0;

        oframe.append(data, start, length);
        spdy.sendFrame(oframe);
    }

    private void maybeCommit() {
        if (outCommit) {
            return;
        }
        if (!response.isCommitted()) {
            // Validate and write response headers
            try {
                sendSynReply();
            } catch (IOException e) {
                e.printStackTrace();
                // Set error flag
                error = true;
                return;
            }
        }
    }
    
    @Override
    public void action(ActionCode actionCode, Object param) {
        System.err.println(actionCode);

        // TODO: async
        
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
    
    /**
     * When committing the response, we have to validate the set of headers, as
     * well as setup the response filters.
     */
    protected void sendSynReply() throws IOException {

        response.setCommitted(true);

        // Special headers
        MimeHeaders headers = response.getMimeHeaders();
        String contentType = response.getContentType();
        if (contentType != null) {
            headers.setValue("Content-Type").setString(contentType);
        }
        String contentLanguage = response.getContentLanguage();
        if (contentLanguage != null) {
            headers.setValue("Content-Language").setString(contentLanguage);
        }
        long contentLength = response.getContentLengthLong();
        if (contentLength >= 0) {
            headers.setValue("Content-Length").setLong(contentLength);
        }

        sendResponseHead();
    }
    
    private void sendResponseHead() throws IOException {
        SpdyFrame rframe = spdy.getFrame(SpdyFramer.TYPE_SYN_REPLY);
        rframe.flags = 0;
        rframe.streamId = channelId;
        rframe.associated = 0;
        
        MimeHeaders headers = response.getMimeHeaders();
        for (int i = 0; i < headers.size(); i++) {
            MessageBytes mb = headers.getName(i);
            mb.toBytes();
            ByteChunk bc = mb.getByteChunk();
            byte[] bb = bc.getBuffer();
            for (int j = bc.getStart(); j < bc.getEnd(); j++) {
                bb[j] = (byte) Ascii.toLower(bb[j]);
            }
            rframe.headerName(bc.getBuffer(), bc.getStart(),  bc.getLength());
            mb = headers.getValue(i);
            mb.toBytes();
            bc = mb.getByteChunk();
            rframe.headerValue(bc.getBuffer(), bc.getStart(),  bc.getLength());
        }
        rframe.headerName(STATUS, 0, STATUS.length);
        

        if (response.getStatus() == 0) {
            rframe.headerValue(OK200, 0, OK200.length);            
        } else {
            // HTTP header contents
            String message = null;
            if (org.apache.coyote.Constants.USE_CUSTOM_STATUS_MSG_IN_HEADER &&
                    HttpMessages.isSafeInHttpHeader(response.getMessage())) {
                message = response.getMessage();
            }
            if (message == null){
                message = HttpMessages.getMessage(response.getStatus());
            }
            if (message == null) {
                // mod_jk + httpd 2.x fails with a null status message - bug 45026
                message = Integer.toString(response.getStatus());
            }
            // TODO: optimize
            String status = response.getStatus() + " " + message;
            byte[] statusB = status.getBytes();
            rframe.headerValue(statusB, 0, statusB.length);            
        }
        rframe.headerName(VERSION, 0, VERSION.length);
        rframe.headerValue(HTTP11, 0, HTTP11.length);
        
        spdy.sendFrame(rframe);
        // we can't reuse the frame - it'll be queued, the coyote processor
        // may be reused as well.
        outCommit = true;
    }

    @Override
    protected boolean isComet() {
        return false;
    }

    @Override
    public SocketState process(SocketWrapper<LightProcessor> socket)
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

    @Override
    public boolean isFinished() {
        return finSent && finRcvd;
    }

}
