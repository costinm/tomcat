/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;

import junit.framework.TestCase;

import org.apache.tomcat.jni.AprSocketContext;
import org.apache.tomcat.spdy.SpdyClientApr.SpdyFramerAprSocket;

/**
 * External test - get google /
 */
public class SpdyClientExternalTest extends TestCase {

    public void testSSLG() throws IOException {
        testSSL("www.google.com", 443);
    }

    public void testSSL(String host, int port) throws IOException {
        SpdyClientApr client = new SpdyClientApr();

        client.setTarget(host, port);

        SpdyClient.ClientSpdyStream stream = client.get("/");

        SpdyFrame f;
        int dataLen = 0;
        while ((f = stream.getIn(10000)) != null) {
            dataLen += f.getDataSize();
        }
        assertEquals(stream.resHeaders.get("status"), "200 OK");

        assertEquals("spdy/2", ((SpdyFramerAprSocket) (client.spdy)).socket
                .getPeerInfo().getNpn());
    }

}
