/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;


/** 
 * Handles SPDY channels.
 */
public interface SpdyChannelProcessor {

    /**
     * Non-blocking, called when a data frame is received.
     * 
     * The processor must consume the data, or set frame.data to 
     * null or a fresh buffer ( to avoid a copy ). 
     */
    void onDataFrame(SpdyFrame currentInFrame);

    /** 
     * Non-blocking - handles a syn stream package.
     * The processor must consume frame.data or set it to null.
     * 
     * If the processor needs to block - implement Runnable, will
     * be scheduled after this call.
     */
    void onSynStream(SpdyFrame frame) throws IOException;
    
}