/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.jni.Error;
import org.apache.tomcat.jni.SSLExt;
import org.apache.tomcat.jni.Status;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AprEndpoint;
import org.apache.tomcat.util.net.LightHandler;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.SocketWrapper;

public class TomcatAprHandler implements LightHandler {
    private static final Log log = LogFactory.getLog(AprEndpoint.class);

    private SpdyContext spdyContext;

    boolean ssl = true;

    @Override
    public void init(final AbstractEndpoint ep, long sslContext) {
        if (sslContext == 0) {
            // Apr endpoint without SSL.
            ssl = false;
            spdyContext = new SpdyContext() {
                @Override
                public SpdyStream getStream(SpdyFramer framer) {
                    return new SpdyTomcatProcessor(framer, ep).getStream();
                }

                public Executor getExecutor() {
                    return ep.getExecutor();
                }
            };
            return;
        }
        if (0 == SSLExt.setNPN(sslContext, SpdyContext.SPDY_NPN_OUT)) {
            spdyContext = new SpdyContext() {
                @Override
                public SpdyStream getStream(SpdyFramer framer) {
                    return new SpdyTomcatProcessor(framer, ep).getStream();
                }

                public Executor getExecutor() {
                    return ep.getExecutor();
                }
            };
        } else {
            log.warn("SPDY/NPN not supported");
        }
    }

    public static class SpdyFramerApr extends SpdyFramer implements
            LightHandler {
        volatile long socket;

        SocketWrapper<Long> socketW;

        boolean ssl;

        boolean closed = false;

        public SpdyFramerApr(SocketWrapper<Long> socketW,
                SpdyContext spdyContext, boolean ssl) {
            super(spdyContext);
            this.socketW = socketW;
            this.socket = socketW.getSocket().longValue();
            this.ssl = ssl;
            if (ssl) {
                setCompressSupport(new CompressJzlib());
            }
        }

        // TODO: write/read should go to SocketWrapper.
        @Override
        public int write(byte[] data, int off, int len) {
            if (socket == 0 || closed) {
                return -1;
            }
            int rem = len;
            while (rem > 0) {
                int sent = org.apache.tomcat.jni.Socket.send(socket, data, off,
                        rem);
                if (sent < 0) {
                    closed = true;
                    return -1;
                }
                if (sent == 0) {
                    return len - rem;
                }
                rem -= sent;
                off += sent;
            }
            return len;
        }

        /**
         */
        @Override
        public int read(byte[] data, int off, int len) throws IOException {
            if (socket == 0 || closed) {
                return 0;
            }
            int rd = org.apache.tomcat.jni.Socket.recv(socket, data, off, len);
            if (rd == -Status.APR_EOF) {
                closed = true;
                return -1;
            }
            if (rd == -Status.TIMEUP) {
                rd = 0;
            }
            if (rd == -Status.EAGAIN) {
                rd = 0;
            }
            if (rd == -70014) {
                rd = 0;
            }
            if (rd < 0) {
                // all other errors
                closed = true;
                throw new IOException("Error: " + rd + " "
                        + Error.strerror((int) -rd));
            }
            off += rd;
            len -= rd;
            return rd;
        }

//        @Override
//        @SuppressWarnings(value = { "rawtypes" })
//        public SocketWrapper getSocket() {
//            return socketW;
//        }

        @Override
        public Object getGlobal() {
            return null;
        }

        @Override
        public void recycle() {
        }

        @Override
        public void init(AbstractEndpoint ep, long aprSspContext) {
        }

        @Override
        public SocketState process(SocketWrapper socket, SocketStatus status) {
            int rc = onBlockingSocket();
            return (rc == SpdyFramer.LONG) ? SocketState.LONG
                    : SocketState.CLOSED;
        }

        @Override
        public void onClose(SocketWrapper<Long> socketWrapper) {
        }

    }
    
    @Override
    public Object getGlobal() {
        return null;
    }

    @Override
    public void recycle() {
    }
    
 // apr normally creates a new object on each poll.
    // For 'upgraded' protocols we need to remember it's handled differently.
    Map<Long, LightHandler> lightProcessors = 
            new HashMap<Long, LightHandler>();

    @Override
    public SocketState process(SocketWrapper socketO, SocketStatus status) {
        SocketWrapper<Long> socketW = socketO;
        long socket = ((Long) socketW.getSocket()).longValue();
        
        LightHandler lh = lightProcessors.get(socket);
        if (lh != null) {
            return lh.process(socketO, status);
        }
        
        if (!ssl || SSLExt.checkNPN(socket, SpdyContext.SPDY_NPN)) {
            // NPN negotiated or not ssl
            SpdyFramerApr ch = new SpdyFramerApr(socketW, spdyContext, ssl);
            return ch.process(socketO, status);
        } else {
            return null;
        }
    }

    @Override
    public void onClose(SocketWrapper<Long> socketWrapper) {
        LightHandler wrapper = lightProcessors.remove(socketWrapper);
        if (wrapper != null) {
            wrapper.onClose(socketWrapper);
        }
    }

    
}
