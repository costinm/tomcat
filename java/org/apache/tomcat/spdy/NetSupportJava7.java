/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.apache.tomcat.spdy.NetSupportSocket.SpdyConnectionSocket;
import org.apache.tomcat.util.net.NioChannel;
import org.apache.tomcat.util.net.SocketWrapper;
import org.eclipse.jetty.npn.NextProtoNego;
import org.eclipse.jetty.npn.NextProtoNego.ClientProvider;


public class NetSupportJava7 extends SpdyContext.NetSupport {

    List<String> protos = Arrays.asList(new String[] {"spdy/2", "http/1.1"});

    private final class SpdyNpnProvider implements NextProtoNego.ServerProvider {
        String selected;
        
        @Override
        public void unsupported() {
        }

        @Override
        public List<String> protocols() {
            return protos;
        }

        @Override
        public void protocolSelected(String protocol) {
            selected = protocol;
        }
    }

    public void onCreateEngine(Object engine) {
        NextProtoNego.debug = true;
        NextProtoNego.put((SSLSocket) engine, new SpdyNpnProvider());

    }
    
    public boolean isSpdy(Object socketW) {
        if (socketW instanceof SSLSocket) {
            SpdyNpnProvider provider = 
                    (SpdyNpnProvider) NextProtoNego.get((SSLSocket) socketW);
            if (provider != null && "spdy/2".equals(provider.selected)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SpdyConnection getConnection(String host, int port)
            throws IOException {
        try {
            Socket sock = getSocket(host, port);

            sock.getInputStream();
            SpdyConnectionSocket con = new SpdyConnectionSocket(ctx, sock);

            ctx.getExecutor().execute(con.inputThread);
            return con;
        } catch (IOException ex) {
            ex.printStackTrace();
            throw ex;
        }
    }
    
    public void onAccept(Object socket) {
        SpdyConnectionSocket ch = new SpdyConnectionSocket(ctx, (Socket) socket);
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

}
