/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;

import org.apache.tomcat.jni.Status;
import org.apache.tomcat.jni.socket.AprSocket;
import org.apache.tomcat.jni.socket.AprSocketContext;
import org.apache.tomcat.jni.socket.AprSocketContext.TlsCertVerifier;

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

    public AprSocketContext getAprContext() {
        return con;
    }    

    public static class SpdyConnectionAprSocket extends SpdyConnection {
        AprSocket socket;

        Runnable inputThread = new Runnable() {
            @Override
            public void run() {
                onBlockingSocket();
                try {
                    socket.writeEnd();
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
                return 0;
            }
            int rd = socket.read(data, off, len);
            // org.apache.tomcat.jni.Socket.recv(socket, data, off, len);
            if (rd == -Status.APR_EOF) {
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

}
