/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;

import org.apache.tomcat.jni.Status;
import org.apache.tomcat.jni.socket.AprSocket;
import org.apache.tomcat.jni.socket.AprSocketContext;
import org.apache.tomcat.jni.socket.AprSocketContext.TlsCertVerifier;
import org.apache.tomcat.jni.socket.AprSocketHandler;

public class SpdyContextJni extends SpdyContext {
    AprSocketContext con;

    public SpdyContextJni() {
        con = new AprSocketContext();
        //if (insecureCerts) {
        con.customVerification(new TlsCertVerifier() {
            @Override
            public void handshakeDone(AprSocket ch) {
            }
        });
        //}
        con.setNpn("spdy/2");
    }
    
    @Override
    public SpdyConnection getConnection(String host, int port) throws IOException {
        SpdyConnectionAprSocket spdy = new SpdyConnectionAprSocket(this);
        
        AprSocket ch = con.socket(host, port, true);

        spdy.setSocket(ch);

        ch.connect();

        getExecutor().execute(spdy.inputThread);
        return spdy;
    }
    
    public SpdyConnection getConnection(AprSocket ch, boolean needTP) {
        SpdyConnectionAprSocket spdy = new SpdyConnectionAprSocket(this);
        spdy.setSocket(ch);

        if (needTP) {
            getExecutor().execute(spdy.inputThread);
        } else {
            spdy.inputThread.run();
        }
        return spdy;
    }

    
    AprSocketContext socketCtx;
    
    public void listen(final int port, String cert, String key) throws IOException {
        socketCtx = new AprSocketContext() {
            protected void onSocket(AprSocket s) throws IOException {
                SpdySocketHandler handler = new SpdySocketHandler();
                s.setHandler(handler);
            }
        };
        
        socketCtx.setNpn(SpdyContext.SPDY_NPN_OUT);
        socketCtx.setKeys(cert, key);
        
        socketCtx.listen(port);
    }

    public void stop() throws IOException {
        socketCtx.stop();
    }
    
    public AprSocketContext getAprContext() {
        return con;
    } 
    
    class SpdySocketHandler implements AprSocketHandler {
        SpdyConnection con;
        
        @Override
        public void process(AprSocket ch) throws IOException {
            getConnection(ch, false);
        }

        @Override
        public void closed(AprSocket ch) {
            // not used ( polling not implemented yet )
        }
        
    }

    public static class SpdyConnectionAprSocket extends SpdyConnection {
        AprSocket socket;

        Runnable inputThread = new Runnable() {
            @Override
            public void run() {
                int rc;
                do {
                    rc = onBlockingSocket();
                } while (rc == SpdyConnection.LONG);
                
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };

        public SpdyConnectionAprSocket(SpdyContext spdyContext) {
            super(spdyContext);
            //setCompressSupport(new CompressJzlib());
            setCompressSupport(new CompressDeflater6());
        }

        public void setSocket(AprSocket ch) {
            this.socket = ch;
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
        
        @Override
        public int write(byte[] data, int off, int len) throws IOException {
            if (socket == null) {
                return -1;
            }
            int sent = socket.write(data, off, len);
            if (sent < 0) {
                return -1;
            }
            return sent;
        }

        /**
         * @throws IOException
         */
        @Override
        public int read(byte[] data, int off, int len) throws IOException {
            if (socket == null) {
                return -1;
            }
            int rd = socket.read(data, off, len);
            // org.apache.tomcat.jni.Socket.recv(socket, data, off, len);
            if (rd == -Status.APR_EOF) {
                return -1;
            }
            if (rd == -Status.TIMEUP || rd == -Status.EINTR || rd == -Status.EAGAIN) {
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

}
