/*
 */
package org.apache.coyote.spdy;

import java.io.IOException;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;

import org.apache.coyote.Adapter;
import org.apache.coyote.http11.Http11AprProtocol;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.jni.Error;
import org.apache.tomcat.jni.SSLExt;
import org.apache.tomcat.jni.Status;
import org.apache.tomcat.spdy.CompressJzlib;
import org.apache.tomcat.spdy.SpdyContext;
import org.apache.tomcat.spdy.SpdyFramer;
import org.apache.tomcat.spdy.SpdyStream;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.AprEndpoint;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.SocketWrapper;

public class SpdyAprNpnHandler implements Http11AprProtocol.NpnHandler {

    private static final Log log = LogFactory.getLog(AprEndpoint.class);

    private SpdyContext spdyContext;

    boolean ssl = true;

    @Override
    public void init(final AbstractEndpoint ep, long sslContext, 
            final Adapter adapter) {
        if (sslContext == 0) {
            // Apr endpoint without SSL.
            ssl = false;
            spdyContext = new SpdyContext() {
                @Override
                public SpdyStream getStream(SpdyFramer framer) {
                    SpdyProcessor sp = new SpdyProcessor(framer, ep);
                    sp.setAdapter(adapter);
                    return sp.getStream();
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
                    SpdyProcessor sp = new SpdyProcessor(framer, ep);
                    sp.setAdapter(adapter);
                    return sp.getStream();
                }

                public Executor getExecutor() {
                    return ep.getExecutor();
                }
            };
        } else {
            log.warn("SPDY/NPN not supported");
        }
    }

    public static class SpdyFramerApr extends SpdyFramer {
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

        public SocketState process(SocketWrapper socket, SocketStatus status) {
            int rc = onBlockingSocket();
            return (rc == SpdyFramer.LONG) ? SocketState.LONG
                    : SocketState.CLOSED;
        }

        public void onClose(SocketWrapper<Long> socketWrapper) {
        }
    }
    
    // apr normally creates a new object on each poll.
    // For 'upgraded' protocols we need to remember it's handled differently.
    Map<Long, SpdyFramerApr> lightProcessors = 
            new HashMap<Long, SpdyFramerApr>();

    @Override
    public SocketState process(SocketWrapper<Long> socketO, SocketStatus status,
            Http11AprProtocol proto, AbstractEndpoint endpoint) {
        
        SocketWrapper<Long> socketW = socketO;
        long socket = ((Long) socketW.getSocket()).longValue();

        SpdyFramerApr lh = lightProcessors.get(socket);
        // Are we getting an HTTP request ? 
        if (lh == null && status != SocketStatus.OPEN) {
            return null;
        }

        log.info("Status: " + status);

        SocketState ss = null;
        if (lh != null) {
            // STOP, ERROR, DISCONNECT, TIMEOUT -> onClose
            if (status == SocketStatus.TIMEOUT) {
                // Called from maintain - we're removed from the poll
                ((AprEndpoint) endpoint).getCometPoller().add(
                        socketO.getSocket().longValue(), false); 
                return SocketState.LONG;
            }
            if (status == SocketStatus.STOP || status == SocketStatus.DISCONNECT ||
                    status == SocketStatus.ERROR) {
                SpdyFramerApr wrapper = lightProcessors.remove(socket);
                if (wrapper != null) {
                    wrapper.onClose();
                }
                return SocketState.CLOSED;
            }
            ss = lh.process(socketO, status);
        } else {
            // OPEN, no existing socket
            if (!ssl || SSLExt.checkNPN(socket, SpdyContext.SPDY_NPN)) {
                // NPN negotiated or not ssl
                SpdyFramerApr ch = new SpdyFramerApr(socketW, spdyContext, ssl);
                
                ss = ch.process(socketO, status);
                if (ss == SocketState.LONG) {
                    lightProcessors.put(socketO.getSocket().longValue(), ch);
                }
            } else {
                return null;
            }
        }
        
        // OPEN is used for both 'first time' and 'new connection'
        // In theory we shouldn't get another open while this is in 
        // progress ( only after we add back to the poller )

        if (ss == SocketState.LONG) {
            log.info("Long poll: " + status);
            ((AprEndpoint) endpoint).getCometPoller().add(
                    socketO.getSocket().longValue(), false); 
        }
        return ss;
    }
    
    public void onClose(SocketWrapper<Long> socketWrapper) {
    }

    
}
