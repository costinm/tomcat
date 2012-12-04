/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.apache.tomcat.spdy.NetSupportSocket.SpdyConnectionSocket;
import org.eclipse.jetty.npn.NextProtoNego;
import org.eclipse.jetty.npn.NextProtoNego.ClientProvider;

/**
 * SSL negotiation using regular sockets and Jetty NPN implementation for Java7. 
 */
public class NetSupportJava7 extends SpdyContext.NetSupport {

    private final class SpdyNpnProvider implements NextProtoNego.ServerProvider {
        String selected;
        
        @Override
        public void unsupported() {
        }

        @Override
        public List<String> protocols() {
            return npnSupportedList;
        }

        @Override
        public void protocolSelected(String protocol) {
            selected = protocol;
        }
    }

    @Override
    public void onCreateEngine(Object engine) {
        NextProtoNego.debug = true;
        NextProtoNego.put((SSLSocket) engine, new SpdyNpnProvider());

    }

    @Override
    public String getNpn(Object socketW) {
        if (socketW instanceof SSLSocket) {
            SpdyNpnProvider provider = 
                    (SpdyNpnProvider) NextProtoNego.get((SSLSocket) socketW);
            if (provider != null) {
                return provider.selected;
            }
        }
        return null;
    }

    @Override
    public SpdyConnection getConnection(String host, int port)
            throws IOException {
        try {
            Socket sock = getSocket(host, port);

            sock.getInputStream();
            SpdyConnectionSocket con = new SpdyConnectionSocket(ctx, sock, getNpn(sock));

            ctx.getExecutor().execute(con.inputThread);
            return con;
        } catch (IOException ex) {
            ex.printStackTrace();
            throw ex;
        }
    }
    
    public void onAccept(Object socket) {
        SpdyConnectionSocket ch = new SpdyConnectionSocket(ctx, (Socket) socket, getNpn(socket));
        ch.onBlockingSocket();                
    }
    

    protected Socket getSocket(String host, int port) throws IOException {
        try {
            SSLContext sslCtx = SSLContext.getDefault();
            SSLSocket socket = (SSLSocket) sslCtx.getSocketFactory().createSocket(host, port);
            NextProtoNego.put(socket, new ClientProvider() {
                @Override
                public boolean supports()
                {
                    return true;
                }

                @Override
                public void unsupported()
                {
                }

                @Override
                public String selectProtocol(List<String> strings)
                {
                    String protocol = strings.get(0);
                    return protocol;
                }

            });
            
            //socket.setEnabledProtocols(new String[] {"TLS1"});
            socket.startHandshake();
            return socket;
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        
    }

    @Override
    public void listen(int port, String cert, String key) throws IOException {
    }

    @Override
    public void stop() throws IOException {
    }

}
