/*
 */
package org.apache.coyote.spdy;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.concurrent.Executor;

import org.apache.coyote.AbstractProtocol;
import org.apache.coyote.ajp.Constants;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.spdy.SpdyContext;
import org.apache.tomcat.spdy.SpdyFramer;
import org.apache.tomcat.spdy.SpdyStream;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.JIoEndpoint;
import org.apache.tomcat.util.net.SSLImplementation;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.SocketWrapper;

public class SpdyProtocol extends AbstractProtocol {
    private static final Log log = LogFactory.getLog(SpdyProtocol.class);
    
    JIoEndpoint.Handler cHandler = new TomcatJioHandler();
    private SpdyContext spdyContext;
    
    public SpdyProtocol() {
        endpoint = new JIoEndpoint();
        ((JIoEndpoint) endpoint).setHandler(cHandler);
        setSoLinger(Constants.DEFAULT_CONNECTION_LINGER);
        setSoTimeout(Constants.DEFAULT_CONNECTION_TIMEOUT);
        setTcpNoDelay(Constants.DEFAULT_TCP_NO_DELAY);
    }
    
    @Override
    protected Log getLog() {
        return log;
    }

    @Override
    protected String getNamePrefix() {
        return "spdy2-jio";
    }

    @Override
    protected String getProtocolName() {
        return "spdy2";
    }

    @Override
    protected Handler getHandler() {
        return cHandler;
    }
    
    public void start() throws Exception {
        super.start();
        spdyContext = new SpdyContext() {
            @Override
            public SpdyStream getStream(SpdyFramer framer) {
                SpdyProcessor sp = new SpdyProcessor(framer, endpoint);
                sp.setAdapter(adapter);
                return sp.getStream();
            }

            public Executor getExecutor() {
                return endpoint.getExecutor();
            }
        };
    }
    
    public class TomcatJioHandler implements JIoEndpoint.Handler {

        @Override
        public Object getGlobal() {
            return null;
        }

        @Override
        public void recycle() {
        }

        @Override
        public SocketState process(SocketWrapper<Socket> socket,
                SocketStatus status) {
            SpdyFramerJio ch = new SpdyFramerJio(spdyContext,
                    (SocketWrapper<Socket>) socket);
            return ch.process(socket, status);
        }

        @Override
        public SSLImplementation getSslImplementation() {
            return null;
        }

    }

    public static class SpdyFramerJio extends SpdyFramer {
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
            try {
                return socket.getInputStream().read(data, off, len);
            } catch (SocketTimeoutException ex) {
                return 0;
            }
        }

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
    }

}
