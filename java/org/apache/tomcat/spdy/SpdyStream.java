/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;


/**
 * One SPDY stream. 
 * 
 * Created by SpdyContext.getProcessor(framer).
 *
 * The methods are called in a IO thread when the framer received a frame
 * for this stream. 
 * 
 *  They should not block.
 *  
 *  The frame must be either consumed or popInFrame must be called, after
 *  the call is done the frame will be reused. 
 */
public interface SpdyStream {

    /**
     * Non-blocking, called when a data frame is received.
     * 
     * The processor must consume the data, or set frame.data to 
     * null or a fresh buffer ( to avoid a copy ). 
     */
    void onDataFrame();

    /** 
     * Non-blocking - handles a syn stream package.
     * The processor must consume frame.data or set it to null.
     * 
     * If the processor needs to block - implement Runnable, will
     * be scheduled after this call.
     */
    void onCtlFrame() throws IOException;
 
    /**
     * True if the channel both received and sent FIN frames.
     * 
     * This is tracked by the processor, to avoid extra storage in framer.
     */
    boolean isFinished();
}