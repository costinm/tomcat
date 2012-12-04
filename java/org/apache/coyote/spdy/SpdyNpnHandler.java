/*
 */
package org.apache.coyote.spdy;

import java.io.IOException;
import java.net.Socket;

import org.apache.coyote.Adapter;
import org.apache.coyote.http11.NpnHandler;
import org.apache.tomcat.spdy.NetSupportJava7;
import org.apache.tomcat.spdy.SpdyConnection;
import org.apache.tomcat.spdy.SpdyContext;
import org.apache.tomcat.spdy.SpdyContext.SpdyHandler;
import org.apache.tomcat.spdy.SpdyStream;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.SocketWrapper;


public class SpdyNpnHandler implements NpnHandler<Socket> {

    SpdyContext spdyContext;
    
    @Override
    public SocketState process(SocketWrapper<Socket> socketW, SocketStatus status) {
        String npn = spdyContext.getNetSupport().getNpn(socketW.getSocket());
        if (npn != null && npn.startsWith("spdy/")) {
            spdyContext.getNetSupport().onAccept(socketW.getSocket(), npn);
            return SocketState.CLOSED;
        }
        return SocketState.OPEN;
   }
    
    @Override
    public void init(final AbstractEndpoint endpoint, long sslCtx,
            final Adapter adapter) {
        spdyContext = new SpdyContext();
        spdyContext.setHandler(new SpdyHandler() {
            @Override
            public void onStream(SpdyConnection con, SpdyStream ch) throws IOException {
                SpdyProcessor sp = new SpdyProcessor(con, endpoint);
                sp.setAdapter(adapter);
                sp.onSynStream(ch);
            }
        });
        spdyContext.setNetSupport(new NetSupportJava7());
    }

    @Override
    public void onCreateEngine(Object socket) {
        SocketWrapper<Socket> socketW = (SocketWrapper<Socket>) socket;
        spdyContext.getNetSupport().onCreateEngine(socketW.getSocket());
    }    
}
