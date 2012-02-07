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
    
    protected SpdyFrame inFrame;
    
    protected LightChannel socket;
    
    protected CompressSupport compressSupport;
    
    // Fields stored for each spdy connection
    Map<Integer, SpdyStream> channels = new HashMap<Integer, SpdyStream>();

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
    
    public SpdyFrame getFrame(int type) {
        SpdyFrame frame = spdyContext.getFrame();
        frame.c = true;
        frame.type = type;
        return frame;
    }

    public SpdyFrame getDataFrame() throws IOException {
        SpdyFrame frame = spdyContext.getFrame();
        return frame;
    }

    int outStreamId = 1;
    
    // TODO: this is a basic test impl - needs to be fixed
    // We need it to be non-blocking, queue the frames - and handle
    // priorities and flow control.
    public void sendFrame(SpdyFrame oframe) throws IOException {
        sendFrame(oframe, null);
    }
    
    public void startStream(SpdyFrame oframe,
            SpdyStream proc) throws IOException {
        sendFrame(oframe, proc);
    }
    
    private void sendFrame(SpdyFrame oframe,
                SpdyStream proc) throws IOException {
        oframe.endData = oframe.off;
        oframe.off = 0;
        if (oframe.type == TYPE_SYN_STREAM) {
            oframe.fixNV(18);
            if (compressSupport != null) {
                compressSupport.compress(oframe, 18);
            }            
        } else if(oframe.type == TYPE_SYN_REPLY ||
                oframe.type == TYPE_HEADERS) {
            oframe.fixNV(14);
            if (compressSupport != null) {
                compressSupport.compress(oframe, 14);
            }
        }
        if (oframe.type == TYPE_SYN_STREAM) {
            oframe.streamId = outStreamId;
            outStreamId += 2;
            channels.put(oframe.streamId, proc);
        }
            
        oframe.serializeHead();
        
        System.err.println("> " + oframe);
        socket.write(oframe.data, 0, oframe.endData);        
    }
    

    public void onClose() {
        // TODO: abort
    }
    
    private void trace(String s) {
        System.err.println(s);
    }
    
    public SpdyFrame popInFrame() {
        SpdyFrame res = inFrame;
        inFrame = null;
        return res;
    }
    
    public SpdyFrame inFrame() {
        return inFrame;
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

    private SpdyFrame nextFrame;
    
    private int handleLiteChannel() throws IOException {
        while (true) {
            if (inFrame == null) {
                inFrame = spdyContext.getFrame();
            }
            
            if (inFrame.data == null) {
                inFrame.data = new byte[16 * 1024];
            }
            // we might already have data from previous frame
            if (inFrame.endData < 8 || // we don't have the header
                    inFrame.endData < inFrame.endFrame) { // size != 0 - we parsed the header
                int rd = socket.read(inFrame.data, inFrame.endData, 
                        inFrame.data.length - inFrame.endData);
                if (rd < 0) {
                    abort("Closed");
                    return CLOSE;
                }
                if (rd == 0) {
                    return OPEN; 
                    // Non-blocking channel - will resume reading at off
                }
                inFrame.endData += rd;
            }
            if (inFrame.endData < 8) {
                continue; // keep reading 
            }
            // We got the frame head
            if (inFrame.endFrame == 0) {
                inFrame.parse();
                if (inFrame.version != 2) {
                    abort("Wrong version");
                    return CLOSE;
                }

                // MAx_FRAME_SIZE
                if (inFrame.endFrame < 0 || inFrame.endFrame > 32000) {
                    abort("Framing error, size = " + inFrame.endFrame);
                    return CLOSE;
                }

                // grow the buffer if needed. no need to copy the head, parsed
                // ( maybe for debugging ).
                if (inFrame.data.length < inFrame.endFrame) {
                    inFrame.data = new byte[inFrame.endFrame];
                }
            }
            
            if (inFrame.endData < inFrame.endFrame) {
                continue; // keep reading to fill current frame
            }
            // else: we have at least the current frame
            int extra = inFrame.endData - inFrame.endFrame;
            if (extra > 0) {
                // and a bit more - to keep things simple for now we 
                // copy them to next frame, at least we saved reads.
                // it is possible to avoid copy - but later.
                nextFrame = spdyContext.getFrame();
                nextFrame.makeSpace(extra);
                System.arraycopy(inFrame.data, inFrame.endFrame, 
                        nextFrame.data, 0, extra);
                nextFrame.endData = extra;
                inFrame.endData = inFrame.endFrame;
            }

            // decompress
            if (inFrame.type == TYPE_SYN_STREAM) {
                inFrame.streamId = inFrame.readInt(); // 4
                lastChannel = inFrame.streamId;
                inFrame.associated = inFrame.readInt(); // 8
                inFrame.read16(); // 10 pri and unused
                if (compressSupport != null) {
                    compressSupport.decompress(inFrame, 18);
                }
                inFrame.nvCount = inFrame.read16();
                
            } else if (inFrame.type == TYPE_SYN_REPLY || 
                    inFrame.type == TYPE_HEADERS) {
                inFrame.streamId = inFrame.readInt(); // 4
                inFrame.read16();
                if (compressSupport != null) { 
                    compressSupport.decompress(inFrame, 14);
                }
                inFrame.nvCount = inFrame.read16();                
            }

            System.err.println("< " + inFrame);
            
            try {
                int state = handleFrame();
                if (state == CLOSE) {
                    return state;
                }
            } catch (Throwable t) {
                abort("Error handling frame");
                t.printStackTrace();
                return CLOSE; 
            }
            
            if (inFrame != null) {
                inFrame.recyle();
                if (nextFrame != null) {
                    spdyContext.releaseFrame(inFrame);
                    inFrame = nextFrame;
                    nextFrame = null;
                }
            } else {
                inFrame = nextFrame;
                nextFrame = null;
                if (inFrame == null) {
                    inFrame = spdyContext.getFrame();
                }
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
    public int handleFrame() throws IOException {
        if (inFrame.c) {
            switch (inFrame.type) {
            case TYPE_SETTINGS: {
                int cnt = inFrame.readInt();
                for (int i = 0; i < cnt; i++) {
                    int flag = inFrame.readByte();
                    int id = inFrame.read24(); 
                    int value = inFrame.readInt();
                }
                break;
                // receivedHello = currentInFrame;
            }
            case TYPE_GOAWAY: {
                int lastStream = inFrame.readInt();
                log.info("GOAWAY last=" + lastStream);
                abort("GOAWAY");
                return LightProtocol.CLOSE;
            } 
            case TYPE_RST_STREAM: {
                inFrame.streamId = inFrame.read32();
                int errCode = inFrame.read32();
                trace("> RST " + inFrame.streamId + " " + 
                        ((errCode < RST_ERRORS.length) ? RST_ERRORS[errCode] : errCode));
                SpdyStream sch = channels.get(inFrame.streamId);
                if (sch == null) {
                    abort("Missing channel " + inFrame.streamId);
                    return LightProtocol.CLOSE;
                }
                sch.onCtlFrame();
                break;
            }
            case TYPE_SYN_STREAM: {

                SpdyStream ch = spdyContext.getProcessor(this);
                
                synchronized (channels) {
                    channels.put(inFrame.streamId, ch);                    
                }

                try {
                    ch.onCtlFrame();        
                } catch (Throwable t) {
                    log.info("Error parsing head SYN_STREAM" + t);
                    abort("Error reading headers " + t);
                    return LightProtocol.CLOSE;
                }
                break;
            } 
            case TYPE_SYN_REPLY: {
                SpdyStream sch = channels.get(inFrame.streamId);
                if (sch == null) {
                    abort("Missing channel");
                    return LightProtocol.CLOSE;
                }
                try {
                    sch.onCtlFrame();        
                } catch (Throwable t) {
                    log.info("Error parsing head SYN_STREAM" + t);
                    abort("Error reading headers " + t);
                    return LightProtocol.CLOSE;
                }
                break;
            }   
            case TYPE_PING: {

                SpdyFrame oframe = currentOutFrame;
                oframe.type = TYPE_PING;
                oframe.c = true;
                oframe.flags = 0;

                oframe.off = 0;
                oframe.data = inFrame.data;
                oframe.endData = inFrame.endData;

                sendFrame(oframe);
                break;
            } 
            }
        } else {
            // Data frame 
            SpdyStream sch = channels.get(inFrame.streamId);
            if (sch == null) {
                abort("Missing channel");
                return LightProtocol.CLOSE;
            }
            sch.onDataFrame();
        }
        return LightProtocol.OPEN;
    }
    
    /**
     * Abstract compression support. When using spdy on intranet ( between
     * load balancer and tomcat) there is no need for the compression overhead.
     * There are also multiple possible implementations.
     */
    public static interface CompressSupport { 
        public void compress(SpdyFrame frame, int start) throws IOException;
        public void decompress(SpdyFrame frame, int start) throws IOException;
    }

    public SpdyContext getContext() {
        return spdyContext;
    }
}


