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
import java.util.HashMap;
import java.util.Map;

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
public abstract class SpdyFrameHandler {

    // Fields stored for each spdy connection
    Map<Integer, SpdyChannelProcessor> channels = new HashMap<Integer, SpdyChannelProcessor>();

    protected SpdyFramer spdyFramer;
    protected AbstractEndpoint endpoint;

    // -------------- 
    protected static final Log log = LogFactory.getLog(SpdyFrameHandler.class);
    
    static int TYPE_HELO = 4; // SETTINGS
    
    static int TYPE_PING = 6; 

    static int TYPE_GOAWAY = 7; 

    static int TYPE_SYN_STREAM = 1;

    static int TYPE_SYN_REPLY = 2;

    static int FLAG_HALF_CLOSE = 1;

    protected SpdyFrame currentOutFrame = new SpdyFrame();

    public SpdyFrameHandler(AbstractEndpoint endpoint, SpdyFramer framer) {
        this.endpoint = endpoint;
        this.spdyFramer = framer;
    }
    
    // Framing error or shutdown- close all streams.
    public void abort(String msg) throws IOException {
        System.err.println(msg);
        
        // TODO: close all streams
    }
    
    /** 
     * Process a SPDY connection. Called in a separate thread.
     * @return 
     * @throws IOException 
     */
    public int handleFrame(SpdyFrame frame, 
            SpdyFramer spdy) throws IOException {
        if (frame.c) {
            if (frame.type == TYPE_HELO) {
                int cnt = frame.readInt();
                for (int i = 0; i < cnt; i++) {
                    int flag = frame.readByte();
                    int id = frame.read24(); 
                    int value = frame.readInt();
                    log.debug("HELO: " + flag + " " + id + " " + value);
                }
                // receivedHello = currentInFrame;
            } else if (frame.type == TYPE_GOAWAY) {
                int lastStream = frame.readInt();
                log.info("GOAWAY last=" + lastStream);
                abort("GOAWAY");
                return LightProtocol.CLOSE;
            } else if (frame.type == TYPE_SYN_STREAM) {

                SpdyChannelProcessor ch = createProcessor();
                ch.setChannelId(frame.streamId);

                synchronized (channels) {
                    channels.put(frame.streamId, ch);                    
                }

                try {
                    ch.request(frame);        
                } catch (Throwable t) {
                    log.error("Error parsing head SYN_STREAM", t);
                    abort("Error reading headers " + t);
                    return LightProtocol.CLOSE;
                }

                if ((frame.flags & FLAG_HALF_CLOSE) != 0) {
                    ch.dataFrame(null);
                }
            } else if (frame.type == TYPE_PING) {

                SpdyFrame oframe = currentOutFrame;
                oframe.type = TYPE_PING;
                oframe.c = true;
                oframe.flags = 0;

                oframe.off = 0;
                oframe.data = frame.data;
                oframe.size = frame.size;

                spdyFramer.sendFrame(oframe);
                
            } else if (frame.type == TYPE_SYN_REPLY) {
                //                    int chId = SpdyConnection.readInt(iob); // 4
                //                    HttpMessage reqch;
                //                    synchronized (channels) {
                //                        reqch = channels.get(chId);
                //                        if (reqch == null) {
                //                            abort("Channel not found");
                //                        }
                //                    }
                //                    HttpMessage resBytes = reqch.peer;
                //                    
                //                    try {
                //                        SpdyConnection.readShort(iob); // 6
                //                        BBuffer head = processHeaders(iob, resBytes, 6);
                //                    } catch (Throwable t) {
                //                        log.log(Level.SEVERE, "Error parsing head SYN_REPLY", t);
                //                        abort("Error reading headers " + t);
                //                        return;
                //                    }
                //
                //                    if ((frame.flags & FLAG_HALF_CLOSE) != 0) {
                //                        resBytes.body.close();
                //                    }
                //                    handler.headers(this, reqch, resBytes);
            }                
        } else {
            // Data frame 
            SpdyChannelProcessor sch = channels.get(frame.streamId);
            if (sch == null) {
                abort("Missing channel");
                return LightProtocol.CLOSE;
            }
            sch.dataFrame(frame);
        }
        return LightProtocol.OPEN;
    }
    
    protected abstract SpdyChannelProcessor createProcessor();
    
}


