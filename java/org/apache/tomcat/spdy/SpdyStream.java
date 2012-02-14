/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * One SPDY stream.
 * 
 * Created by SpdyContext.getProcessor(framer).
 * 
 * The methods are called in a IO thread when the framer received a frame for
 * this stream.
 * 
 * They should not block.
 * 
 * The frame must be either consumed or popInFrame must be called, after the
 * call is done the frame will be reused.
 */
public abstract class SpdyStream {
    SpdyFramer spdy;

    SpdyFrame reqFrame;

    SpdyFrame resFrame;

    BlockingQueue<SpdyFrame> inData = new LinkedBlockingQueue<SpdyFrame>();

    public static final SpdyFrame END_FRAME = new SpdyFrame(16);

    boolean finSent;

    boolean finRcvd;

    /**
     * Non-blocking, called when a data frame is received.
     * 
     * The processor must consume the data, or set frame.data to null or a fresh
     * buffer ( to avoid a copy ).
     */
    public void onDataFrame(SpdyFrame inFrame) {
        inData.add(inFrame);
        if (inFrame.closed()) {
            finRcvd = true;
            inData.add(END_FRAME);
        }
    }

    /**
     * Non-blocking - handles a syn stream package. The processor must consume
     * frame.data or set it to null.
     * 
     * If the processor needs to block - implement Runnable, will be scheduled
     * after this call.
     */
    public abstract void onCtlFrame(SpdyFrame frame) throws IOException;

    /**
     * True if the channel both received and sent FIN frames.
     * 
     * This is tracked by the processor, to avoid extra storage in framer.
     */
    public boolean isFinished() {
        return finSent && finRcvd;
    }

    public SpdyFrame getIn(long to) throws IOException {
        SpdyFrame in;
        try {
            if (inData.size() == 0 && finRcvd) {
                return null;
            }
            in = inData.poll(to, TimeUnit.MILLISECONDS);

            if (in == END_FRAME) {
                return null;
            }
            return in;
        } catch (InterruptedException e) {
            throw new IOException(e);
        }
    }
}