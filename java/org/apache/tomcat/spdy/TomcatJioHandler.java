/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.Executor;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.LightHandler;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.SocketWrapper;

public class TomcatJioHandler implements LightHandler {

    private SpdyContext spdyContext;

    @Override
    public void init(final AbstractEndpoint ep, long unused) {
        spdyContext = new SpdyContext() {
            @Override
            public SpdyStream getStream(SpdyFramer framer) {
                return new SpdyTomcatProcessor(framer, ep).getStream();
            }

            public Executor getExecutor() {
                return ep.getExecutor();
            }
        };
    }

    public static class SpdyFramerJio extends SpdyFramer implements
            LightHandler {
        Socket socket;

        private SocketWrapper<Socket> socketW;

        public SpdyFramerJio(SpdyContext spdyContext,
                SocketWrapper<Socket> socketW) {
            super(spdyContext);
            this.socketW = socketW;
            this.socket = socketW.getSocket();
        }

        // TODO: read/write should go to SocketWrapper.
        @Override
        public int write(byte[] data, int off, int len) throws IOException {
            socket.getOutputStream().write(data, off, len);
            return len;
        }

        @Override
        public int read(byte[] data, int off, int len) throws IOException {
            return socket.getInputStream().read(data, off, len);
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
        public SocketState process(SocketWrapper socketW, SocketStatus status) {
            try {
                socket.setSoTimeout(60000);
            } catch (SocketException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            onBlockingSocket();
            return SocketState.CLOSED;
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

    @Override
    @SuppressWarnings(value = { "rawtypes", "unchecked" })
    public SocketState process(SocketWrapper socket, SocketStatus status) {
        SpdyFramerJio ch = new SpdyFramerJio(spdyContext, (SocketWrapper<Socket>) socket);
        return ch.process(socket, status);
    }

    @Override
    public void onClose(SocketWrapper<Long> socketWrapper) {
    }
}
