/*
 */
package org.apache.coyote.spdy;

import java.io.IOException;

import javax.net.ssl.SSLEngine;

import org.apache.coyote.Adapter;
import org.apache.coyote.http11.NpnHandler;
import org.apache.tomcat.spdy.SpdyConnection;
import org.apache.tomcat.spdy.SpdyContext;
import org.apache.tomcat.spdy.SpdyContext.SpdyHandler;
import org.apache.tomcat.spdy.SpdyStream;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.NioChannel;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.SocketWrapper;


public class SpdyNioNpnHandler implements NpnHandler<NioChannel> {

    SpdyContext spdyContext;
    
    @Override
    public SocketState process(SocketWrapper<NioChannel> socket, SocketStatus status) {
        SocketWrapper<NioChannel> socketW = (SocketWrapper<NioChannel>) socket;
        NioChannel channel = socketW.getSocket();
        String npn = spdyContext.getNetSupport().getNpn(socketW.getSocket());
        if (npn != null && npn.startsWith("spdy/")) {
            spdyContext.getNetSupport().onAccept(socketW, npn);
                
            return SocketState.CLOSED;
        }
        return SocketState.OPEN;
   }
    
    @Override
    public void init(final AbstractEndpoint endpoint, long sslContext, final Adapter adapter) {
        spdyContext = new SpdyContext();
        spdyContext.setHandler(new SpdyHandler() {
            @Override
            public void onStream(SpdyConnection con, SpdyStream ch)
                    throws IOException {
                SpdyProcessor sp = new SpdyProcessor(con, endpoint);
                sp.setAdapter(adapter);
                sp.onSynStream(ch);
            }
        });
        NetSupportTomcatNio netSupport = new NetSupportTomcatNio();
        netSupport.pool = ((NioEndpoint) endpoint).getSelectorPool();
        spdyContext.setNetSupport(netSupport);
    }

    @Override
    public void onCreateEngine(Object engine) {
        spdyContext.getNetSupport().onCreateEngine((SSLEngine) engine);
    }
    
}
