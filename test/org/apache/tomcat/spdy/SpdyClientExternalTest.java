/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;

import junit.framework.TestCase;

import org.apache.tomcat.jni.socket.HostInfo;
import org.apache.tomcat.spdy.SpdyContext.NetSupport;

/**
 * External test - get google /
 */
public class SpdyClientExternalTest extends TestCase {
    SpdyContext spdyContext = new SpdyContext();

    public void testSSLG() throws IOException {
        testSSLSession("www.google.com", 443);
    }

    public void testSimple() throws IOException {
        get(spdyContext, "www.google.com", 443, "/");
    }
    
    public static void get(SpdyContext spdyContext, 
            String host, int port, String path) throws IOException {

        SpdyConnection client = spdyContext.getConnection(host, port);

        SpdyClient.get(client, host, port, path);
    }
    
    public void testSSLSession(String host, int port) throws IOException {
        SpdyConnection client = spdyContext.getConnection(host, port);
        SpdyClient.get(client, host, port, "/");
        
        SpdyStream stream = client.get(host, "/");
                
        // Send again, to verify ticket is working
        NetSupport ns = spdyContext.getNetSupport();
        if (ns instanceof NetSupportOpenSSL) {
            NetSupportOpenSSL nsossl = (NetSupportOpenSSL) ns;
            HostInfo hostInfo = nsossl.getAprContext().getHostInfo(host, port, true);
            assertEquals("spdy/2", hostInfo.getNpn());
            hostInfo.setNpn(null);
            //assertTrue(hostInfo.ticketLen > 0);

            // We got the certs
            assertTrue(hostInfo.certs.length > 0);

            hostInfo.certs = null; // reset them for the next connection

            // same APR context, new connection
            client = spdyContext.getConnection(host, port);
            SpdyClient.get(client, host, port, "/");

            assertEquals("spdy/2", hostInfo.getNpn());

            // Send again, to verify ticket is working
            //assertTrue(hostInfo.ticketLen > 0);

            // No certs this time ( ticket or session reuse skipped them )
            assertTrue(hostInfo.certs.length == 0);

        }
    }

    public static void main(String args[]) throws IOException {
        if (args.length == 0) {
            args = new String[] { "www.google.com", "443", "/" };
        }
        // TODO: CLI parsing
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String url = args[2];
        
        SpdyContext spdyContext = new SpdyContext();

        SpdyConnection client = spdyContext.getConnection(host, port);

        client.get(host, url);

    }
    
}
