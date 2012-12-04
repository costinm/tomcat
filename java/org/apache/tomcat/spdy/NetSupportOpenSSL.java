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

import org.apache.tomcat.jni.SSLExt;
import org.apache.tomcat.jni.Status;
import org.apache.tomcat.jni.socket.AprSocket;
import org.apache.tomcat.jni.socket.AprSocketContext;
import org.apache.tomcat.jni.socket.AprSocketContext.NonBlockingPollHandler;

/**
 * Support SPDY NPN using apr and openssl (jni).
 * Requires latest tomcat jni and openssl > 1.0. 
 */
public class NetSupportOpenSSL extends SpdyContext.NetSupport {

    AprSocketContext con;

    public NetSupportOpenSSL() {
        con = new AprSocketContext();
        //if (insecureCerts) {
//        con.customVerification(new TlsCertVerifier() {
//            @Override
//            public void handshakeDone(AprSocket ch) {
//            }
//        });
        //}
        con.setNpn(npnSupportedBytes);
    }

    @Override
    public String getNpn(Object socketW) {
        byte[] proto = new byte[32];
        int len = SSLExt.getNPN(((Long) socketW).longValue(), proto);
        if (len < 1) {
            return null;
        }
        return new String(proto, 0, len);
    }

    @Override
    public SpdyConnection getConnection(String host, int port) throws IOException {

        AprSocket ch = con.socket(host, port, ctx.tls);

        ch.connect();
        String proto = ch.getHost().getNpn();
        if (ctx.tls && !proto.startsWith("spdy/")) {
            throw new IOException("SPDY not supported");
        }

        SpdyConnectionAprSocket spdy = new SpdyConnectionAprSocket(ctx, proto);
        spdy.setSocket(ch);

        ch.setHandler(new SpdySocketHandler(spdy));

        // need to consume the input to receive more read events
        int rc = spdy.processInput();
        if (rc == SpdyConnection.CLOSE) {
            ch.close();
            throw new IOException("Error connecting");
        }

        return spdy;
    }

    @Override
    public void onAccept(Object socket, String proto) {
        onAcceptLong((Long) socket, proto);
    }
    
    public void onAcceptLong(long socket, String proto) {
        SpdyConnectionAprSocket spdy = new SpdyConnectionAprSocket(ctx, proto);
        AprSocket s = con.socket(socket);
        spdy.setSocket(s);

        SpdySocketHandler handler = new SpdySocketHandler(spdy);
        s.setHandler(handler);
        handler.process(s, true, true, false);
    }

    public AprSocketContext getAprContext() {
        return con;
    }

    @Override
    public void listen(final int port, String cert, String key) throws IOException {
        con = new AprSocketContext() {
            @Override
            protected void onSocket(AprSocket s) {
                SpdyConnectionAprSocket spdy = new SpdyConnectionAprSocket(ctx, s.getHost().getNpn());
                spdy.setSocket(s);

                SpdySocketHandler handler = new SpdySocketHandler(spdy);
                s.setHandler(handler);
            }
        };

        con.setNpn(npnSupportedBytes);
        con.setKeys(cert, key);

        con.listen(port);
    }

    @Override
    public void stop() throws IOException {
        con.stop();
    }

    // NB
    static class SpdySocketHandler implements NonBlockingPollHandler {
        SpdyConnection con;

        SpdySocketHandler(SpdyConnection con) {
            this.con = con;
        }

        @Override
        public void closed(AprSocket ch) {
            // not used ( polling not implemented yet )
        }

        @Override
        public void process(AprSocket ch, boolean in, boolean out, boolean close) {
            try {
                int rc = con.processInput();
                if (rc == SpdyConnection.CLOSE) {
                    ch.close();
                }
                con.drain();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                ch.reset();
            }
        }

        @Override
        public void connected(AprSocket ch) {
        }

        @Override
        public void error(AprSocket ch, Throwable t) {
        }

    }

    public static class SpdyConnectionAprSocket extends SpdyConnection {
        AprSocket socket;

        public SpdyConnectionAprSocket(SpdyContext spdyContext, String proto) {
            super(spdyContext, proto);
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

    public byte[] getProtocolBytes() {
        return npnSupportedBytes;
    }


}
