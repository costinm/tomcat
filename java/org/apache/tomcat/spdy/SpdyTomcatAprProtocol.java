/*
 */
package org.apache.tomcat.spdy;

import java.net.Socket;
import java.util.concurrent.Executor;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.jni.SSLExt;
import org.apache.tomcat.jni.Status;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AprEndpoint;
import org.apache.tomcat.util.net.LightProcessor;
import org.apache.tomcat.util.net.LightProtocol;

public class SpdyTomcatAprProtocol implements LightProtocol {
    private static final Log log = LogFactory.getLog(AprEndpoint.class);

    private SpdyContext spdyContext;
    
    public LightProcessor getProcessor(long socket) {
        if (SSLExt.checkNPN(socket, SpdyContext.SPDY_NPN)) {
            // NPN negotiated
            return new SpdyFramerApr(socket, spdyContext);
        } else {
            return null;
        }
    }

    @Override
    public void init(long sslContext, final AbstractEndpoint ep) {
        if (0 == SSLExt.setNPN(sslContext, SpdyContext.SPDY_NPN_OUT)) {
            spdyContext = new SpdyContext() {
                @Override
                public SpdyStream getStream(SpdyFramer framer) {
                    return new SpdyTomcatProcessor(framer, ep);
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
        long socket;
        
        public SpdyFramerApr(long socket, SpdyContext spdyContext) {
            super(spdyContext);
            this.socket = socket;
            setCompressSupport(new CompressJzlib());
        }
        
        @Override
        public int write(byte[] data, int off, int len) {
            if (socket == 0) {
                return -1;
            }
            while (len > 0) {
                int sent = org.apache.tomcat.jni.Socket.send(socket, data, off, len);
                if (sent < 0) {
                    return -1;
                }
                len -= sent;
                off += sent;
            }
            return len;
        }

        /**
         */
        @Override
        public int read(byte[] data, int off, int len) {
            if (socket == 0) {
                return 0;
            }
            int rd = org.apache.tomcat.jni.Socket.recv(socket, data, off, len);
            if (rd == - Status.APR_EOF) {
                return 0;
            }
            if (rd == -Status.TIMEUP) {
                rd = 0;
            }
            if (rd == -Status.EAGAIN) {
                rd = 0;
            }

            if (rd < 0) {
                return -1;
            }
            off += rd;
            len -= rd;
            return rd;
        }

    }

    @Override
    public LightProcessor getProcessor(Socket socket) {
        return null;
    }    
}
