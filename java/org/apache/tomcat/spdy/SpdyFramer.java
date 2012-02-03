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
import java.util.concurrent.Executor;
import java.util.logging.Logger;

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
    // TODO: override socket timeout
    
    protected SpdyFrame currentInFrame = new SpdyFrame();

    
    protected LightChannel socket;
    
    protected CompressSupport compressSupport;
    
    int off = 0;
    
    // Fields stored for each spdy connection
    Map<Integer, SpdyChannelProcessor> channels = new HashMap<Integer, SpdyChannelProcessor>();

    // -------------- 
    protected static final Logger log = 
            Logger.getLogger(SpdyFramer.class.getName());
    
    
    static final int TYPE_SYN_STREAM = 1;

    static final int TYPE_SYN_REPLY = 2;

    static final int TYPE_RST_STREAM = 3;

    static final int TYPE_SETTINGS = 4;
    
    static final int TYPE_PING = 6; 

    static final int TYPE_GOAWAY = 7; 

    static final int TYPE_HEADERS = 8; 

    static final int TYPE_WINDOW = 8; 

    public static String[] TYPES = {
        "SYN_STREAM", "SYN_REPLY", "RST_STREAM", "SETTINGS", "5", "PING",
        "GOAWAY", "HEADERS", "WINDOW_UPDATE"
    };
    
    static int FLAG_HALF_CLOSE = 1;

    public static String[] RST_ERRORS = {
       // This is a generic error, and should only be used if a more 
        // specific error is not available.
      "PROTOCOL_ERROR",
      "INVALID_STREAM", 
      // This is returned when a frame is received for a stream which is not 
      // active.
      "REFUSED_STREAM", 
      // Indicates that the stream was refused before any processing has been 
      // done on the stream.
      "UNSUPPORTED_VERSION", 
      // 4 Indicates that the recipient of a stream does not support the 
      // SPDY version requested.
      "CANCEL", 
      // 5 Used by the creator of a stream to indicate that the stream is 
      // no longer needed.
      "FLOW_CONTROL_ERROR", 
      // 6 The endpoint detected that its peer violated the flow control protocol.
      "STREAM_IN_USE", 
      // 7 The endpoint received a SYN_REPLY for a stream already open.
      "STREAM_ALREADY_CLOSED" 
      // 8 The endpoint received a data or SYN_REPLY frame for a stream which 
      //is half closed.
    };
    
    
    protected SpdyFrame currentOutFrame = new SpdyFrame();

    private SpdyContext spdyContext;

    int lastChannel;
    // -------------- 
    
    public static byte[] NPN = "spdy/2".getBytes();
    
    
    public SpdyFramer(LightChannel socket, SpdyContext spdyContext) {
        this.socket = socket;
        this.spdyContext = spdyContext;        
    }

    public void setCompressSupport(CompressSupport cs) {
        compressSupport = cs;
    }

    public synchronized void sendFrame(SpdyFrame oframe) throws IOException {
        if (compressSupport != null &&
            oframe.c && 
                (oframe.type == TYPE_SYN_REPLY || 
                 oframe.type == TYPE_SYN_STREAM)) {
            compressSupport.compress(oframe);
        }
            
        int headlen = oframe.serializeHead();
        socket.write(oframe.head, 0, headlen);

        System.err.println("> " + oframe);
        socket.write(oframe.data, oframe.off, oframe.size);        
    }
    

    public void onClose() {
        // TODO: abort
    }
    
    private void trace(String s) {
        System.err.println(s);
    }
    
    /** 
     * Process a SPDY connection. Called in a separate thread.
     * @throws IOException 
     */
    @Override
    public int onData() {
        try {
            trace("< onData() " + lastChannel);
            int rc = handleLiteChannel();
            trace("< onData() " + rc + " " + lastChannel);            
            return rc;
        } catch (Throwable t) {
            t.printStackTrace();
            trace("< onData-ERROR() " + lastChannel);            
            return CLOSE;
        }
    }

    private int handleLiteChannel() throws IOException {
        while (true) {
            while (off < 8) {
                int rd = socket.read(currentInFrame.head, off, 8 - off);
                if (rd < 0) {
                    abort("Closed");
                    return CLOSE;
                }
                if (rd == 0) {
                    return OPEN; 
                    // Non-blocking channel - will resume reading at off
                }
                off += rd;
            }
            currentInFrame.parse();
            if (currentInFrame.version != 2) {
                abort("Wrong version");
                return CLOSE;
            }
            // MAx_FRAME_SIZE
            if (currentInFrame.size < 0 || currentInFrame.size > 32000) {
                abort("Framing error, size = " + currentInFrame.size);
                return CLOSE;
            }

            if (currentInFrame.data == null 
                    || currentInFrame.data.length < currentInFrame.size) {
                currentInFrame.data = new byte[currentInFrame.size];
            }

            int dataOff = off - 8; // off is total bytes read on this frame
            while (dataOff < currentInFrame.size) {
                int rd = socket.read(currentInFrame.data, dataOff, 
                        currentInFrame.size + dataOff);
                if (rd < 0) {
                    abort("Closed");
                    return CLOSE;
                }
                if (rd == 0) {
                    return OPEN; 
                    // Non-blocking channel - will resume reading at off
                }
                off += rd;
                dataOff += rd;
            }
            // Frame read fully - next onData will process next frame (but we're
            // not done )
            off = 0;
            
            // decompress
            if (currentInFrame.type == TYPE_SYN_STREAM) {
                currentInFrame.streamId = currentInFrame.readInt(); // 4
                lastChannel = currentInFrame.streamId;
                currentInFrame.associated = currentInFrame.readInt(); // 8
                currentInFrame.readShort(); // 10 pri and unused
                if (compressSupport != null) {
                    compressSupport.decompress(currentInFrame);
                }
                currentInFrame.nvCount = currentInFrame.readShort();
                
            } else if (currentInFrame.type == TYPE_SYN_REPLY) {
                currentInFrame.streamId = currentInFrame.readInt(); // 4
                if (compressSupport != null) { 
                    compressSupport.decompress(currentInFrame);
                }
                currentInFrame.nvCount = currentInFrame.readShort();                
            }

            System.err.println("< " + currentInFrame);
            
            try {
                int state = handleFrame(currentInFrame, this);
                if (state == CLOSE) {
                    return state;
                }
            } catch (Throwable t) {
                abort("Error handling frame");
                t.printStackTrace();
                return CLOSE; 
            }
        }
    }
    
    @Override
    public void setSocket(LightChannel socket) {
        this.socket = socket;
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
            switch (frame.type) {
            case TYPE_SETTINGS: {
                int cnt = frame.readInt();
                for (int i = 0; i < cnt; i++) {
                    int flag = frame.readByte();
                    int id = frame.read24(); 
                    int value = frame.readInt();
                }
                break;
                // receivedHello = currentInFrame;
            }
            case TYPE_GOAWAY: {
                int lastStream = frame.readInt();
                log.info("GOAWAY last=" + lastStream);
                abort("GOAWAY");
                return LightProtocol.CLOSE;
            } 
            case TYPE_RST_STREAM: {
                frame.streamId = frame.read32();
                int errCode = frame.read32();
                trace("> RST " + frame.streamId + " " + 
                        ((errCode < RST_ERRORS.length) ? RST_ERRORS[errCode] : errCode));
                SpdyChannelProcessor sch = channels.get(frame.streamId);
                if (sch == null) {
                    abort("Missing channel " + frame.streamId);
                    return LightProtocol.CLOSE;
                }
                // TODO: abort/close the channel
                sch.onDataFrame(frame);
                break;
            }
            case TYPE_SYN_STREAM: {

                SpdyChannelProcessor ch = spdyContext.getProcessor(this);
                
                synchronized (channels) {
                    channels.put(frame.streamId, ch);                    
                }

                try {
                    ch.onSynStream(frame);        
                } catch (Throwable t) {
                    log.info("Error parsing head SYN_STREAM" + t);
                    abort("Error reading headers " + t);
                    return LightProtocol.CLOSE;
                }
                Executor exec = spdyContext.getExecutor();
                
                if (exec != null && ch instanceof Runnable) {
                    exec.execute((Runnable) ch);
                }

                if ((frame.flags & FLAG_HALF_CLOSE) != 0) {
                    ch.onDataFrame(null);
                }
                break;
            } 
            case TYPE_PING: {

                SpdyFrame oframe = currentOutFrame;
                oframe.type = TYPE_PING;
                oframe.c = true;
                oframe.flags = 0;

                oframe.off = 0;
                oframe.data = frame.data;
                oframe.size = frame.size;

                sendFrame(oframe);
                break;
            } 
            case TYPE_SYN_REPLY: {
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
                break;
            }   
            }
        } else {
            // Data frame 
            SpdyChannelProcessor sch = channels.get(frame.streamId);
            if (sch == null) {
                abort("Missing channel");
                return LightProtocol.CLOSE;
            }
            sch.onDataFrame(frame);
        }
        return LightProtocol.OPEN;
    }
    
    /**
     * Abstract compression support. When using spdy on intranet ( between
     * load balancer and tomcat) there is no need for the compression overhead.
     * There are also multiple possible implementations.
     */
    public static interface CompressSupport { 
        public void compress(SpdyFrame frame) throws IOException;
        public void decompress(SpdyFrame frame) throws IOException;
    }
}


