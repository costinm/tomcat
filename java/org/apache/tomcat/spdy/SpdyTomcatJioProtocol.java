/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.Executor;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.LightProcessor;
import org.apache.tomcat.util.net.LightProtocol;

public class SpdyTomcatJioProtocol implements LightProtocol {

    private SpdyContext spdyContext;
    
    public LightProcessor getProcessor(Socket socket) {
        return new SpdyFramerJio(spdyContext, socket);
    }

    @Override
    public void init(long unused, final AbstractEndpoint ep) {
        spdyContext =         new SpdyContext() {
            @Override
            public SpdyStream getStream(SpdyFramer framer) {
                return new SpdyTomcatProcessor(framer, ep);
            }

            public Executor getExecutor() {
                return ep.getExecutor();
            }
        };
    }

    @Override
    public LightProcessor getProcessor(long socket) {
        return null;
    }
    
    
    public static class SpdyFramerJio extends SpdyFramer {
        Socket socket;
        
        public SpdyFramerJio(SpdyContext spdyContext, Socket socket) {
            super(spdyContext);
            this.socket = socket;
        }

        @Override
        public int write(byte[] data, int off, int len) throws IOException {
            socket.getOutputStream().write(data, off, len);
            return len;
        }

        @Override
        public int read(byte[] data, int off, int len) throws IOException {
            return socket.getInputStream().read(data, off, len);
        }
    }    
}
