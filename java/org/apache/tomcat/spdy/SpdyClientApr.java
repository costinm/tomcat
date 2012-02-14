/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;

import org.apache.tomcat.jni.AprSocket;
import org.apache.tomcat.jni.AprSocketContext;
import org.apache.tomcat.jni.Status;

public class SpdyClientApr extends SpdyClient {

    AprSocketContext con = new AprSocketContext();

    @Override
    public void init() {
        spdy = new SpdyFramerAprSocket(spdyCtx);
    }

    public AprSocketContext getSocketContext() {
        return con;
    }

    public class SpdyFramerAprSocket extends SpdyFramer {
        AprSocket socket;

        Runnable inputThread = new Runnable() {
            @Override
            public void run() {
                onBlockingSocket();
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };

        public SpdyFramerAprSocket(SpdyContext spdyContext) {
            super(spdyContext);
            setCompressSupport(new CompressJzlib());
        }

        public void setSocket(AprSocket ch) {
            this.socket = ch;
        }

        protected boolean checkConnection(SpdyFrame oframe) throws IOException {
            if (connected) {
                return true;
            }
            if (connecting) {
                return false;
            }
            connecting = true;

            if (insecureCerts) {
                con.customVerification();
            }
            con.setNpn("spdy/2");

            AprSocket ch = con.channel();
            ch.setTarget(host, port);
            ch.blockingStartTLS();

            ((SpdyFramerAprSocket) spdy).setSocket(ch);

            ch.connect();

            spdyCtx.getExecutor().execute(inputThread);
            connected = true;

            return true;
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
