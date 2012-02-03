/*
 */
package org.apache.tomcat.spdy;

import java.util.concurrent.Executor;

import org.apache.tomcat.spdy.SpdyFramer.CompressSupport;

/** 
 * Will implement polling/reuse of heavy objects, allow additional configuration.
 * 
 *  The abstract methods allow integration with different libraries ( compression,
 *  request handling )
 */
public abstract class SpdyContext {

    public static final byte[] SPDY_NPN; 
    public static final byte[] SPDY_NPN_OUT;
    static {
        SPDY_NPN = "spdy/2".getBytes();
        SPDY_NPN_OUT = new byte[SPDY_NPN.length + 2];
        System.arraycopy(SPDY_NPN, 0, SPDY_NPN_OUT, 1, SPDY_NPN.length);
        SPDY_NPN_OUT[0] = (byte) SPDY_NPN.length;
    }

    private Executor executor;

    public LightProtocol getSpdy(LightChannel socket) {
        SpdyFramer spdyHandler = new SpdyFramer(socket, this);
        spdyHandler.setCompressSupport(getCompressor());
        return spdyHandler;
    }

    public CompressSupport getCompressor() {
        return null;
    }


    public abstract SpdyChannelProcessor getProcessor(SpdyFramer framer);

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
        return executor;
    }
    
}
