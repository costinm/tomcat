/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.util.HashMap;

import junit.framework.TestCase;

import org.apache.tomcat.jni.socket.AprSocketContext;
import org.apache.tomcat.jni.socket.HostInfo;

/**
 * External test - get google /
 */
public class SpdyClientExternalTest extends TestCase {

    public void testSSLG() throws IOException {
        testSSL("www.google.com", 443);
    }

    public void testSSL(String host, int port) throws IOException {
        SpdyContextJni spdyContext = new SpdyContextJni();
        
        SpdyConnection client = spdyContext.getConnection(host, port);
        SpdyStream stream = client.get(host, "/");

        SpdyFrame f;
        int dataLen = 0;
        while ((f = stream.getIn(10000)) != null) {
            dataLen += f.getDataSize();
        }
        HashMap<String, String> resHeaders = new HashMap<String, String>();
        stream.getHeaders(resHeaders);
        assertEquals(resHeaders.get("status"), "200 OK");

        assertTrue(dataLen > 100);
        
        // Send again, to verify ticket is working
        HostInfo hostInfo = spdyContext.getAprContext().getPeerInfo(host, port, true);
        assertEquals("spdy/2", hostInfo.getNpn());
        hostInfo.setNpn(null);
        //assertTrue(hostInfo.ticketLen > 0);
        
        // We got the certs
        assertTrue(hostInfo.certs.length > 0);
        
        hostInfo.certs = null; // reset them for the next connection
        
        // same APR context, new connection
        client = spdyContext.getConnection(host, port);
        stream = client.get(host, "/");

        int dataLen2 = 0;
        while ((f = stream.getIn(10000)) != null) {
            dataLen2 += f.getDataSize();
        }
        resHeaders.clear();
        stream.getHeaders(resHeaders);
        assertEquals(resHeaders.get("status"), "200 OK");

        assertEquals("spdy/2", hostInfo.getNpn());
        assertTrue(dataLen2 > 100);
        
        // Send again, to verify ticket is working
        //assertTrue(hostInfo.ticketLen > 0);
        
        // No certs this time ( ticket or session reuse skipped them )
        assertTrue(hostInfo.certs.length == 0);
        
    }

    public static void main(String args[]) throws IOException {
        if (args.length == 0) {
            args = new String[] { "www.google.com", "443", "/" };
        }
        // TODO: CLI parsing
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String url = args[2];
        
        SpdyContextJni spdyContext = new SpdyContextJni();

        SpdyConnection client = spdyContext.getConnection(host, port);

        client.get(host, url);

    }
    
}
