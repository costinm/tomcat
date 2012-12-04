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
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Entry point for the SPDY implementation.
 * 
 * Use this to create SpdyConnection objects in client mode, or to listen to
 * connections using SpdyHandler callback.
 */
public final class SpdyContext {

    private Executor executor;

    int defaultFrameSize = 8192;

    protected boolean debug = true;

    protected boolean tls = true;
    protected boolean compression = true;

    // Delegate socket creation
    private NetSupport netSupport;

    SpdyHandler handler;


    /**
     * Class implementing the network communication and SSL negotiation. 
     * 
     * Provided: Java7 + JettyNPN, Java6/7 with APR+OpenSSL, Android. 
     * Also in coyote 
     */
    public abstract static class NetSupport {
        protected SpdyContext ctx;
        protected String[] npnSupported = 
                new String[] {"spdy/3", "http/1.1"};
        protected List<String> npnSupportedList = Arrays.asList(npnSupported);
        protected byte[] npnSupportedBytes = getNpnBytes(npnSupported);


        public void setSpdyContext(SpdyContext ctx) {
            this.ctx = ctx;
        }

        /**
         * Client mode: initiate a connection and negotiate SSL / NPN.
         */
        public abstract SpdyConnection getConnection(String host, int port)
                throws IOException;

        public String getNpn(Object socketW) {
            return null;
        }

        public void onAccept(Object socket, String proto) {
        }
        public abstract void listen(int port, String cert, String key)
                throws IOException;

        public abstract void stop() throws IOException;

        public void onCreateEngine(Object engine) {
        }
        
        public static final byte[] getNpnBytes(String[] npns) {
            int len = 0;
            for (int i = 0; i < npns.length; i++) {
                byte[] data = npns[i].getBytes();
                len += data.length + 1;
            }

            byte[] npnB = new byte[len + 1];
            int off = 0;
            for (int i = 0; i < npns.length; i++) {
                byte[] data = npns[i].getBytes();

                npnB[off++] = (byte) data.length;
                System.arraycopy(data, 0, npnB, off, data.length);
                off += data.length;
            }
            npnB[off++] = 0;
            return npnB;
        }
    }

    public SpdyContext() {
    }

    /**
     * By default compression and tls are enabled. Use this to change, for example
     * if a proxy handles TLS or compression.
     */
    public void setTlsComprression(boolean tls, boolean compress) {
        this.tls = tls;
        this.compression = compress;
    }

    /**
     * Get a frame - frames are heavy buffers, may be reused.
     */
    SpdyFrame getFrame(int size) {
        // TODO: pool, reuse. Send will return to pool.
        return new SpdyFrame(size);
    }

    /**
     * Set the max frame size.
     *
     * Larger data packets will be split in multiple frames.
     *
     * ( the code is currently accepting larger control frames - it's not
     * clear if we should just reject them, many servers limit header size -
     * the http connector also has a 8k limit - getMaxHttpHeaderSize )
     */
    public void setFrameSize(int frameSize) {
        defaultFrameSize = frameSize;
    }

    /**
     * Get a Stream object for the given connection.
     * Streams may be pooled/reused. 
     */
    protected SpdyStream getStream(SpdyConnection framer) {
        SpdyStream spdyStream = new SpdyStream(framer);
        return spdyStream;
    }

    /**
     * Use a custom executor
     */
    public void setExecutor(Executor executor) {
        this.executor = executor;
    }


    /** 
     * Use a specific SSL / NPN handler.
     */
    public void setNetSupport(NetSupport netSupport) {
        this.netSupport = netSupport;
        netSupport.setSpdyContext(this);
    }

    /**
     * Return the SSL/NPN handler - if none was set attempt to load APR, if not 
     * available fallback to java socket.
     */
    public NetSupport getNetSupport() {
        if (netSupport == null) {
            for (String nsClass: new String[] {"org.apache.tomcat.spdy.NetSupportOpenSSL",
                    "org.apache.tomcat.spdy.NetSupportJava7",
                    "org.apache.tomcat.spdy.NetSupportSocket"}) {
                try {
                    Class<?> c0 = Class.forName(nsClass);
                    netSupport = (NetSupport) c0.newInstance();
                    break;
                } catch (Throwable t) {
                    // ignore, openssl not supported
                }
                
            }
            if (netSupport != null) {
                netSupport.setSpdyContext(this);
                return netSupport;
            }
            throw new RuntimeException("Missing net support class.");
        }

        return netSupport;
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

    public SpdyHandler getHandler() {
        return handler;
    }

    public void setHandler(SpdyHandler handler) {
        this.handler = handler;
    }

    /**
     * Called when a new strem has been stareted on a connection. 
     */
    public static interface SpdyHandler {
        public void onStream(SpdyConnection spdyCon, SpdyStream ch) throws IOException;

    }

    /**
     * A handler implementing this interface will be called in the 'io' thread - the
     * thread reading the multiplexed stream, and in the case of non-blocking
     * transports also handling polling the socket.
     *
     */
    public static interface NonBlockingSpdyHandler extends SpdyHandler {
    }


    /**
     * Client mode: return a connection for host/port.
     */
    public SpdyConnection getConnection(String host, int port) throws IOException {
        return getNetSupport().getConnection(host, port);
    }

    public final void listen(final int port, String cert, String key) throws IOException {
        getNetSupport().listen(port, cert, key);
    }

    /**
     * Close all pending connections and free resources.
     */
    public final void stop() throws IOException {
        getNetSupport().stop();
    }

    /**
     * Called when a stream has been created - you can override this method, or use 
     * the handler callback.
     */
    public void onStream(SpdyConnection spdyConnection, SpdyStream ch) throws IOException {
        if (handler instanceof NonBlockingSpdyHandler) {
            handler.onStream(spdyConnection, ch);
        } else if (handler instanceof SpdyHandler) {
            getExecutor().execute(ch);
        }
    }
}
