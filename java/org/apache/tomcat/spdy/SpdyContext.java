/*
 */
package org.apache.tomcat.spdy;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/** 
 * Will implement polling/reuse of heavy objects, allow additional configuration.
 * 
 *  The abstract methods allow integration with different libraries ( compression,
 *  request handling )
 *  
 * In 'external' mode it must be used with APR library and compression. 
 * 
 * In 'intranet' mode - it is supposed to be used behind a load balancer
 * that handles SSL and compression.
 * Test with:  --user-data-dir=/tmp/test --use-spdy=no-compress,no-ssl
 */
public class SpdyContext {

    public static final byte[] SPDY_NPN; 
    public static final byte[] SPDY_NPN_OUT;
    static {
        SPDY_NPN = "spdy/2".getBytes();
        SPDY_NPN_OUT = new byte[SPDY_NPN.length + 2];
        System.arraycopy(SPDY_NPN, 0, SPDY_NPN_OUT, 1, SPDY_NPN.length);
        SPDY_NPN_OUT[0] = (byte) SPDY_NPN.length;
    }

    private Executor executor;

    int defaultFrameSize = 8196;
	static boolean debug = true;
    
    /**
     *  Get a frame - frames are heavy buffers, may be reused.
     */
    public SpdyFrame getFrame() {
        return new SpdyFrame(defaultFrameSize);
    }

    public void releaseFrame(SpdyFrame done) {
    }
    
    public SpdyStream getStream(SpdyFramer framer) {
        return null;
    }

    public void setExecutor(Executor executor) {
        this.executor = executor;
    }
    
    /**
     * SPDY is a multiplexed protocol - the SpdyProcessors will be executed on
     * this executor.
     *  
     * If the context returns null - we'll assume the SpdyProcessors are fully
     * non blocking, and will execute them in the spdy thread.
     */
    public Executor getExecutor() {
        if (executor == null) {
            executor = Executors.newCachedThreadPool();
        }
        return executor;
    }
    
}
