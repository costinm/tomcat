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
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One TCP connection to a host, multiplexing multiple SpdyStreams. 
 */
public abstract class SpdyConnection {

    // TODO: this can be pooled, to avoid allocation on idle connections
    // TODO: override socket timeout

    static final int MAX_ALLOWED_FRAME_SIZE = 64 * 1024 * 1024;
    protected static final Logger log = Logger.getLogger(SpdyConnection.class
            .getName());

    public static final int TYPE_SYN_STREAM = 1;

    public static final int TYPE_SYN_REPLY = 2;

    public static final int TYPE_RST_STREAM = 3;

    public static final int TYPE_SETTINGS = 4;

    public static final int TYPE_PING = 6;

    public static final int TYPE_GOAWAY = 7;

    public static final int TYPE_HEADERS = 8;

    public static final int TYPE_WINDOW_UPDATE = 9;

    public static final int LONG = 1;

    public static final int CLOSE = -1;

    public static String[] TYPES = { "SYN_STREAM", "SYN_REPLY", "RST_STREAM",
            "SETTINGS", "5", "PING", "GOAWAY", "HEADERS", "WINDOW_UPDATE" };

    static final int FLAG_FIN = 1;
    static final int FLAG_UNIDIRECTIONAL = 2;

    // Settings flags
    static final int FLAG_SETTINGS_PERSIST_VALUE = 1;
    static final int FLAG_SETTINGS_PERSISTED = 2;

    public static String[] RST_ERRORS = {
            "", // 0 is invalid
            // This is a generic error, and should only be used if a more
            // specific error is not available.
            "PROTOCOL_ERROR",
            "INVALID_STREAM",
            // This is returned when a frame is received for a stream which is
            // not
            // active.
            "REFUSED_STREAM",
            // Indicates that the stream was refused before any processing has
            // been
            // done on the stream.
            "UNSUPPORTED_VERSION",
            // 4 Indicates that the recipient of a stream does not support the
            // SPDY version requested.
            "CANCEL",
            // 5 Used by the creator of a stream to indicate that the stream is
            // no longer needed.
            "INTERNAL_ERROR",
            "FLOW_CONTROL_ERROR",
            // 6 The endpoint detected that its peer violated the flow control
            // protocol.
            "STREAM_IN_USE",
            // 7 The endpoint received a SYN_REPLY for a stream already open.
            "STREAM_ALREADY_CLOSED",
            "INVALID_CREDENTIALS",
            "FRAME_TOO_LARGE"
    };

    public static final String[] SETTINGS = {
            "",
            "UPLOAD_BANDWIDTH",
            "DOWNLOAD_BANDWIDTH",
            "ROUND_TRIP_TIME",
            "MAX_CONCURRENT_STREAMS",
            "CURRENT_CWND",
            "DOWNLOAD_RETRANS_RATE",
            "INITIAL_WINDOW_SIZE",
            "CLIENT_CERTIFICATE_VECTOR_SIZE"
    };

    /**
     *  Frame that is in process of parsing, may be incomplete
     */
    private volatile SpdyFrame inFrame;

    /**
     * We read as much as possible - if we received more data than needed
     * we move any extra to the next frame and process inFrame. nextFrame
     * will become the new inFrame.
     */
    private SpdyFrame nextFrame;

    /**
     * Current frame getting sent. Write may be non-blocking, next time we can
     * write will continue with this frame.
     */
    private SpdyFrame outFrame;

    protected CompressSupport compressSupport;

    protected Map<Integer, SpdyStream> channels = new HashMap<>();

    protected SpdyContext spdyContext;

    protected boolean inClosed;

    protected int lastChannel;

    protected int outStreamId = 0;

    protected int version = 3; // TODO: multiple version support

    // TODO: finer handling of priorities
    private LinkedList<SpdyFrame> priorityQueue = new LinkedList<>();

    private LinkedList<SpdyFrame> outQueue = new LinkedList<>();

    private int goAway = Integer.MAX_VALUE;

    public int maxFrameSize;
    
    public int totalInData;

    public int totalInFrames;

    int frameSize;
    int frameSizeIn;

    protected SpdyConnection(SpdyContext spdyContext, String proto) {
        this.spdyContext = spdyContext;
        this.frameSize = spdyContext.defaultFrameSize;
        this.frameSizeIn = frameSize; // default
        
        if ("spdy/2".equals(proto)) {
            // default is 3
            version = 2;
        }
        if (spdyContext.compression) {
            setCompressSupport(CompressDeflater6.get());
        }
    }

    @Override
    public String toString() {
        return "SpdyCon open=" + channels.size() + " " + lastChannel;
    }

    public void dump(PrintWriter out) {
        out.println("SpdyConnection open=" + channels.size() +
                " outQ:" + outQueue.size() + 
                " framesIn: " + this.totalInFrames +
                " totalInData: " + this.totalInData +
                " maxFrameIn: " + this.maxFrameSize
                );
        for (SpdyStream str: channels.values()) {
            str.dump(out);
        }

        out.println();
    }

    /**
     * Write. May be non-blocking, in which case the actual number of written 
     * bytes is returned. 
     */
    public abstract int write(byte[] data, int off, int len) throws IOException;

    /**
     * Like read, but may return 0 if no data is available and the channel
     * is non-blocking.
     */
    public abstract int read(byte[] data, int off, int len) throws IOException;
    
    public abstract void close() throws IOException;

    public void setCompressSupport(CompressSupport cs) {
        compressSupport = cs;
    }

    /**
     * Get a frame with a specific type.
     * This is for outgoing messages.
     */
    public SpdyFrame getFrame(int type) {
        SpdyFrame frame = getSpdyContext().getFrame(frameSize);
        frame.c = true;
        frame.type = type;
        frame.version = version;
        return frame;
    }

    /** 
     * Get a data frame, that will be populated and sent with send().
     * 
     * This is a lower-level interface than OutputStream, it may allow 
     * polling/reusing the SpdyFrame objects.
     */
    public SpdyFrame getDataFrame() {
        SpdyFrame frame = getSpdyContext().getFrame(frameSize);
        frame.version = version;
        frame.c = false;
        return frame;
    }

   /**
    * Add the frame to the queue and send until the queue is empty.
    * May block if the socket is blocking.
    */
    public void send(SpdyFrame oframe, SpdyStream proc) {
        queueFrame(oframe, proc, outQueue);
        drain();
    }

    /**
     * Send as much as possible without blocking.
     *
     * With a nb transport it should call drain directly.
     */
    public void nonBlockingSend(SpdyFrame oframe, SpdyStream proc, boolean pri) {
        queueFrame(oframe, proc, pri ? outQueue : priorityQueue);
        getSpdyContext().getExecutor().execute(nbDrain);
    }

    /**
     * Send any queued data. Should be used for non-blocking sockets when 
     * socket can write.
     */
    public void drain() {
        synchronized (nbDrain) {
            _drain();
        }
    }

    /**
     * Non blocking if the socket is not blocking.
     */
    private boolean _drain() {
        if (outStreamId == 0) {
            SpdyFrame oframe = getFrame(SpdyConnection.TYPE_SETTINGS);
            oframe.appendCount(1);
            oframe.append32(7);
            oframe.append32(Integer.MAX_VALUE);
            queueFrame(oframe, null, priorityQueue);
            outStreamId = 1;
        }
        while (true) {
            synchronized (outQueue) {
                if (outFrame == null) {
                    outFrame = priorityQueue.poll();
                    if (outFrame == null) {
                        outFrame = outQueue.poll();
                    }
                    if (outFrame == null) {
                        return false;
                    }
                    if (goAway < outFrame.streamId) {
                        // TODO
                    }
                    try {
                        if (!outFrame.c) {
                            // late: IDs are assigned as we send ( priorities may affect
                            // the transmission order )
                            if (outFrame.stream != null) {
                                outFrame.streamId = outFrame.stream.getRequest().streamId;
                            }
                        } else if (outFrame.type == TYPE_SYN_STREAM) {
                            outFrame.fixNV(18);
                            if (compressSupport != null) {
                                compressSupport.compress(outFrame, 18);
                            }
                        } else if (outFrame.type == TYPE_SYN_REPLY
                                || outFrame.type == TYPE_HEADERS) {
                            int headerOffset = version == 2 ? 14 : 12;
                            outFrame.fixNV(headerOffset);
                            if (compressSupport != null) {
                                compressSupport.compress(outFrame,headerOffset);
                            }
                        }
                    } catch (IOException ex) {
                        abort("Compress error");
                        return false;
                    }
                    if (outFrame.type == TYPE_SYN_STREAM) {
                        outFrame.streamId = outStreamId;
                        outStreamId += 2;
                        synchronized(channels) {
                            channels.put(Integer.valueOf(outFrame.streamId),
                                    outFrame.stream);
                        }
                    }
                    if (outFrame.stream != null && outFrame.stream.finSent &&
                            outFrame.isHalfClose()) {
                        trace("Dropping duplicated FIN " + outFrame);
                        outFrame = null;
                        continue;
                    }

                    outFrame.serializeHead();

                }
                if (outFrame.endData == outFrame.off) {
                    outFrame = null;
                    continue;
                }
            }

            if (spdyContext.debug) {
                trace("> " + outFrame);
            }

            try {
                int toWrite = outFrame.endData - outFrame.off;
                int wr;
                while (toWrite > 0) {
                    wr = write(outFrame.data, outFrame.off, toWrite);
                    if (wr < 0) {
                        return false;
                    }
                    if (wr == 0) {
                        return true; // non blocking or to
                    }
                    if (wr <= toWrite) {
                        outFrame.off += wr;
                        toWrite -= wr;
                    }
                }

                synchronized (channels) {
                    if (outFrame.stream != null) {
                        if (outFrame.isHalfClose()) {
                            outFrame.stream.finSent = true;
                        }
                        if (outFrame.stream.finRcvd && outFrame.stream.finSent) {
                            channels.remove(Integer.valueOf(outFrame.streamId));
                        }
                    }
                }
                outFrame = null;
            } catch (IOException e) {
                // connection closed - abort all streams
                log.info("IOException in write " + e.getMessage());
                onClose();
                return false;
            }
        }
    }

    /** 
     * Runnable calling drain().
     */
    Runnable nbDrain = new Runnable() {
        @Override
        public void run() {
            drain();
        }
    };

    private void queueFrame(SpdyFrame oframe, SpdyStream proc,
            LinkedList<SpdyFrame> queue) {

        oframe.endData = oframe.off;
        oframe.off = 0;
        // We can't assing a stream ID until it is sent - priorities
        // we can't compress either - it's stateful.
        oframe.stream = proc;

        // all sync for adding/removing is on outQueue
        synchronized (outQueue) {
            queue.add(oframe);
        }
    }

    public void onClose() {
        // TODO: abort
    }

    private void trace(String s) {
        log.info(s);
    }

    /**
     * Process a SPDY connection using a blocking socket.
     */
    public int onBlockingSocket() {
        try {
            if (spdyContext.debug) {
                trace("< onConnection() " + lastChannel);
            }
            // TODO: if v3, send a SETTINGS size with INITIAL_WINDOW_SIZE == max
            // so we don't need to send WINDOWS_UPDATE ( until we implement the limits )
            int rc = processInput();

            if (spdyContext.debug) {
                trace("< onConnection() " + rc + " " + lastChannel);
            }
            return rc;
        } catch (Throwable t) {
            trace("< onData-ERROR() " + lastChannel);
            t.printStackTrace();
            abort("Error processing socket" + t);
            return CLOSE;
        }
    }

    /**
     * Non-blocking method, read as much as possible and return.
     */
    public int processInput() throws IOException {
        while (true) {
            if (inFrame == null) {
                inFrame = getSpdyContext().getFrame(frameSizeIn);
            }

            if (inFrame.data == null) {
                inFrame.data = new byte[16 * 1024];
            }
            // we might already have data from previous frame
            if (inFrame.endReadData < 8 || // we don't have the header
                    inFrame.endReadData < inFrame.endData) {
                int rd = 0;
                rd = read(inFrame.data, inFrame.endReadData,
                        inFrame.data.length - inFrame.endReadData);
                if (rd == -1) {
                    if (channels.size() == 0) {
                        return CLOSE;
                    } else {
                        abort("Closed");
                        return CLOSE;
                    }
                } else if (rd < 0) {
                    abort("Closed - read error");
                    return CLOSE;
                } else if (rd == 0) {
                    return LONG;
                    // Non-blocking channel - will resume reading at off
                }
                inFrame.endReadData += rd;
            }
            if (inFrame.endReadData < 8) {
                continue; // keep reading
            }
            if (inFrame.endData == 0) {
                inFrame.parse(version);
                if (version == 0) { // first frame
                    version = inFrame.version;
                    if (version != 2 && version != 3) {
                        abort("Wrong version");
                        return CLOSE;                        
                    }
                }

                // MAX_FRAME_SIZE
                if (inFrame.endData < 0 || inFrame.endData > 32000) {
                    abort("Framing error, size = " + inFrame.endData);
                    return CLOSE;
                }

                // TODO: if data, split it in 2 frames
                // grow the buffer if needed.
                if (inFrame.data.length < inFrame.endData) {
                    byte[] tmp = new byte[inFrame.endData];
                    System.arraycopy(inFrame.data, 0, tmp, 0, inFrame.endReadData);
                    inFrame.data = tmp;
                }
            }

            if (inFrame.endReadData < inFrame.endData) {
                continue; // keep reading to fill current frame
            }
            // else: we have at least the current frame
            int extra = inFrame.endReadData - inFrame.endData;
            if (extra > 0) {
                // and a bit more - to keep things simple for now we
                // copy them to next frame, at least we saved reads.
                // it is possible to avoid copy - but later.
                nextFrame = getSpdyContext().getFrame(frameSizeIn);
                nextFrame.makeSpace(extra);
                System.arraycopy(inFrame.data, inFrame.endData,
                        nextFrame.data, 0, extra);
                nextFrame.endReadData = extra;
                inFrame.endReadData = inFrame.endData;
            }
            
            // stats
            if (inFrame.endData > this.maxFrameSize) {
                this.maxFrameSize = inFrame.endData;
                if (maxFrameSize > frameSize && maxFrameSize < MAX_ALLOWED_FRAME_SIZE) {
                    frameSizeIn = maxFrameSize;
                }
            }
            this.totalInFrames++;
            this.totalInData += inFrame.endData;

            // decompress
            if (inFrame.type == TYPE_SYN_STREAM) {
                inFrame.streamId = inFrame.readInt(); // 4
                lastChannel = inFrame.streamId;
                inFrame.associated = inFrame.readInt(); // 8
                inFrame.pri = inFrame.read16(); // 10 pri and unused
                if (compressSupport != null) {
                    compressSupport.decompress(inFrame, 18);
                }
                inFrame.nvCount = inFrame.readCount();
                
            } else if (inFrame.type == TYPE_SYN_REPLY
                    || inFrame.type == TYPE_HEADERS) {
                inFrame.streamId = inFrame.readInt(); // 4
                inFrame.read16();
                if (compressSupport != null) {
                    if (version == 2) {
                        compressSupport.decompress(inFrame, 14);
                    } else {
                        compressSupport.decompress(inFrame, 12);                        
                    }
                }
                inFrame.nvCount = inFrame.readCount();
            }

            if (spdyContext.debug) {
                trace("< " + inFrame);
            }

            try {
                int state = handleFrame();
                if (state == CLOSE) {
                    return state;
                }
            } catch (Throwable t) {
                abort("Error handling frame " + t.getMessage());
                return CLOSE;
            }

            if (inFrame != null) {
                inFrame.recyle();
                if (nextFrame != null) {
                    inFrame = nextFrame;
                    nextFrame = null;
                }
            } else {
                inFrame = nextFrame;
                nextFrame = null;
                if (inFrame == null) {
                    inFrame = getSpdyContext().getFrame(frameSizeIn);
                }
            }
        }
    }

    // Framing error or shutdown- close all streams.
    public void abort(String msg) {
        log.log(Level.SEVERE, "Abort: " + msg);
        inClosed = true;

        List<Integer> ch = new ArrayList<>(channels.keySet());
        for (Integer i: ch) {
            SpdyStream stream = channels.remove(i);
            if (stream != null) {
                stream.onReset();
            }
        }
    }

    public void abort(String msg, int last) {
        log.log(Level.SEVERE, "Abort: " + msg + " " + last);
        inClosed = true;

        List<Integer> ch = new ArrayList<>(channels.keySet());
        for (Integer i: ch) {
            if (i.intValue() > last) {
                SpdyStream stream = channels.remove(i);
                if (stream != null) {
                    stream.onReset();
                }
            }
        }
    }

    protected void setSetting(int flag, int id, int value) {
        if (spdyContext.debug) {
            trace("> Setting: " + flag + " " +
                    ((id < SETTINGS.length) ? SETTINGS[id] : id) + value);
        }
    }

    /**
     * Process a SPDY connection. Called in the input thread, should not
     * block.
     *
     * @throws IOException
     */
    protected int handleFrame() throws IOException {
        if (inFrame.c) {
            switch (inFrame.type) {
            case TYPE_SETTINGS: {
                int cnt = inFrame.readInt();
                for (int i = 0; i < cnt; i++) {
                    int flag = inFrame.readByte();
                    int id = inFrame.read24();
                    int value = inFrame.readInt();
                    setSetting(flag, id, value);
                }
                // TODO: save/interpret settings
                break;
            }
            case TYPE_GOAWAY: {
                int lastStream = inFrame.readInt();
                int status = inFrame.readInt();
                log.info("GOAWAY last=" + lastStream + " " + status);

                // Server will shut down - but will keep processing the current requests,
                // up to lastStream. If we sent any new ones - they need to be canceled.
                abort("GO_AWAY", lastStream);
                goAway  = lastStream;
                return CLOSE;
            }
            case TYPE_RST_STREAM: {
                inFrame.streamId = inFrame.read32();
                int errCode = inFrame.read32();
                if (spdyContext.debug) {
                    trace("> RST "
                            + inFrame.streamId
                            + " "
                            + ((errCode < RST_ERRORS.length) ? RST_ERRORS[errCode]
                                    : Integer.valueOf(errCode)));
                }
                SpdyStream sch;
                synchronized(channels) {
                        sch = channels.remove(
                                Integer.valueOf(inFrame.streamId));
                }
                // if RST stream is for a closed channel - we can ignore.
                if (sch != null) {
                    sch.onReset();
                }

                inFrame = null;
                break;
            }
            case TYPE_SYN_STREAM: {

                SpdyStream ch = getSpdyContext().getStream(this);

                synchronized (channels) {
                    channels.put(Integer.valueOf(inFrame.streamId), ch);
                }

                try {
                    ch.onCtlFrame(inFrame);
                    inFrame = null;
                } catch (Throwable t) {
                    log.log(Level.SEVERE, "Error parsing head SYN_STREAM", t);
                    abort("Error reading headers " + t);
                    return CLOSE;
                }
                spdyContext.onStream(this, ch);
                break;
            }
             case TYPE_WINDOW_UPDATE: {
                 // Default initial: 64K

                 int streamId = inFrame.readInt();
                 int delta = inFrame.readInt();


                 break;
             }
            case TYPE_SYN_REPLY: {
                SpdyStream sch;
                synchronized(channels) {
                    sch = channels.get(Integer.valueOf(inFrame.streamId));
                }
                if (sch == null) {
                    abort("Missing channel");
                    return CLOSE;
                }
                try {
                    sch.onCtlFrame(inFrame);
                    inFrame = null;
                } catch (Throwable t) {
                    log.info("Error parsing head SYN_STREAM" + t);
                    abort("Error reading headers " + t);
                    return CLOSE;
                }
                break;
            }
            case TYPE_PING: {

                SpdyFrame oframe = getSpdyContext().getFrame(32);
                oframe.type = TYPE_PING;
                oframe.c = true;
                inFrame.associated = oframe.associated = inFrame.read32();

                oframe.append32(oframe.associated);

                nonBlockingSend(oframe, null, true);
                break;
            }
            }
        } else {
            // Data frame
            SpdyStream sch;
            synchronized (channels) {
                sch = channels.get(Integer.valueOf(inFrame.streamId));
            }
            if (sch == null) {
                abort("Missing channel");
                return CLOSE;
            }
            sch.onDataFrame(inFrame);
            synchronized (channels) {
                if (sch.finRcvd && sch.finSent) {
                    channels.remove(Integer.valueOf(inFrame.streamId));
                }
            }
            inFrame = null;
        }
        return LONG;
    }

    public SpdyContext getSpdyContext() {
        return spdyContext;
    }

    public SpdyStream get(String host, String url) {
        SpdyStream sch = new SpdyStream(this);
        sch.setUrl(host, url);
        
        sch.send();

        return sch;
    }

    /**
     * Abstract compression support. When using spdy on intranet ( between load
     * balancer and tomcat) there is no need for the compression overhead. There
     * are also multiple possible implementations.
     */
    static interface CompressSupport {
        public void compress(SpdyFrame frame, int start) throws IOException;

        public void decompress(SpdyFrame frame, int start) throws IOException;
    }
}
