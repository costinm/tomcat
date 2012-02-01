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

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;

/**
 * Handle SPDY protocol.
 *
 * Because we need to auto-detect SPDY and fallback to HTTP ( based on SSL
 * next proto ) this is implemented in a special way: 
 * AbstractHttp11Processor.process() will delegate to Spdy.process if spdy 
 * is needed.
 * 
 * 
 */
public class SpdyFramer implements LightProtocol {

    // TODO: this can be pooled, to avoid allocation on idle connections
    protected SpdyFrame currentInFrame = new SpdyFrame();


    protected SpdyFrameHandler handler;
    
    protected LightChannel socket;
    
    // -------------- 
    protected static final Log log = LogFactory.getLog(SpdyFramer.class);
    
    public static byte[] NPN = "spdy/2".getBytes();
    
    
    public SpdyFramer(LightChannel socket) {
        this.socket = socket;
    }

    public void setHandler(SpdyFrameHandler handler) {
        this.handler = handler;
    }

    public synchronized void sendFrame(SpdyFrame oframe) throws IOException {
        if (oframe.c && 
                (oframe.type == SpdyFrameHandler.TYPE_SYN_REPLY || 
                 oframe.type == SpdyFrameHandler.TYPE_SYN_STREAM)) {
            compress(oframe);
        }
            
        int headlen = oframe.serializeHead();
        socket.write(oframe.head, 0, headlen);

        System.err.println("> " + oframe);
        socket.write(oframe.data, oframe.off, oframe.size);        
    }
    

    private int readAll(byte[] data, int off, int len) throws IOException {
        while (len > 0) {
            int rd = socket.read(data, off, len);
            if (rd < 0) {
                return rd;
            }
            len -= rd;
            off += rd;
        }
        return 0;
    }
    
    public void onClose() {
        // TODO: abort
    }
    
    /** 
     * Process a SPDY connection. Called in a separate thread.
     * @throws IOException 
     */
    @Override
    public int onData() {
        try {
            return handleLiteChannel();
        } catch (Throwable t) {
            t.printStackTrace();
            return CLOSE;
        }
    }

    private int handleLiteChannel() throws IOException {
        while (true) {
            int rd = readAll(currentInFrame.head, 0, 8);
            if (rd < 0) {
                handler.abort("Closed");
                return CLOSE;
            }
            currentInFrame.parse();
            if (currentInFrame.version != 2) {
                handler.abort("Wrong version");
                return CLOSE;
            }
            // MAx_FRAME_SIZE
            if (currentInFrame.size < 0 || currentInFrame.size > 32000) {
                handler.abort("Framing error, size = " + currentInFrame.size);
            }

            if (currentInFrame.data == null || currentInFrame.data.length < currentInFrame.size) {
                currentInFrame.data = new byte[currentInFrame.size];
            }

            readAll(currentInFrame.data, 0, currentInFrame.size);
            
            // decompress
            if (currentInFrame.type == SpdyFrameHandler.TYPE_SYN_STREAM) {
                currentInFrame.streamId = currentInFrame.readInt(); // 4
                currentInFrame.associated = currentInFrame.readInt(); // 8
                // pri and unused
                currentInFrame.readShort(); // 10
                decompress(currentInFrame);
                
                currentInFrame.nvCount = currentInFrame.readShort();
                
            } else if (currentInFrame.type == SpdyFrameHandler.TYPE_SYN_REPLY) {
                currentInFrame.streamId = currentInFrame.readInt(); // 4
                decompress(currentInFrame);
                
                currentInFrame.nvCount = currentInFrame.readShort();                
            }

            System.err.println("< " + currentInFrame);
            
            try {
                int state = handler.handleFrame(currentInFrame, this);
                if (state == CLOSE) {
                    return state;
                }
            } catch (Throwable t) {
                handler.abort("Error handling frame");
                t.printStackTrace();
                return CLOSE; 
            }
        }
    }
    
    protected void compress(SpdyFrame frame) throws IOException {
    }

    protected void decompress(SpdyFrame frame) 
            throws IOException {
    }

    // Hack to avoid direct dependency on the new tc_native methods
    // and on jzlib
    public static void setNPN(long sslContext) {
        // TODO: use introspection
        SpdyFramerNPN.setNPN(sslContext);
    }


    public static LightProtocol getSpdy(LightChannel socket, String spdy,
            AbstractEndpoint endpoint) {
        SpdyFramer spdyHandler = null;
        if ("npn".equals(spdy)) {
            if (SpdyFramerNPN.checkNPN(socket)) {
                spdyHandler = new SpdyFramerNPN(socket);
            }
        } else {
            // forced spdy - but without compression or npn check
            spdyHandler = new SpdyFramer(socket);
        }
        if (spdyHandler != null) {
            spdyHandler.setHandler(new SpdyFrameHandler(endpoint, spdyHandler) {

                @Override
                protected SpdyChannelProcessor createProcessor() {
                    return new SpdyCoyoteProcessor(spdyFramer, endpoint);
                }
                
            });
        }
        
        return spdyHandler;
    }

    @Override
    public void setSocket(LightChannel socket) {
        this.socket = socket;
    }

}


