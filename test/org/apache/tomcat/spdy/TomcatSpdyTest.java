/*
 */
package org.apache.tomcat.spdy;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.HashMap;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.net.TesterSupport;
import org.junit.Before;
import org.junit.Test;

public class TomcatSpdyTest extends TomcatBaseTest {

    boolean realSpdy = false;

    SpdyContext spdyCtx;
    SpdyConnection client;
    String host = "localhost";
    
    protected void extraConnectorSetup(Connector connector, String protocol) {
        if (port != 0) {
            connector.setPort(port);
        }
        if ("org.apache.coyote.spdy.SpdyProxyProtocol".equals(protocol)) {
            spdyCtx = new SpdyContext();
        } else if ("org.apache.coyote.http11.Http11AprProtocol"
                .equals(protocol)) {
            connector.setProperty("npnHandler", 
                    "org.apache.coyote.spdy.SpdyAprNpnHandler");
            
            spdyCtx = new SpdyContext();
            realSpdy = true;
            Tomcat tomcat = getTomcatInstance();
            TesterSupport.initSsl(tomcat);
        }
        
    }
    
    protected String getProtocol() {
        String protocol = System.getProperty("tomcat.test.protocol");

        // Use BIO by default
        if (protocol == null) {
            protocol = "org.apache.coyote.spdy.SpdyProxyProtocol";
        }
        return protocol;
    }
    
    int port = 0;
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        Tomcat tomcat = getTomcatInstance();
        Context root = tomcat.addContext("", TEMP_DIR);

        Tomcat.addServlet(root, "hello", new HelloWorldServlet());
        root.addServletMapping("/hello", "hello");

        tomcat.start();
        client = spdyCtx.getConnection(host, getPort());
    }

    @Test
    public void testGet1() throws Exception {
        get();
    }

    public void get() throws IOException {
        SpdyClient.get(client, host, 0, "/hello");
    }

    int to = 20000;

    public void getNParallel(int n) throws IOException {
        SpdyStream[] streams = new SpdyStream[n];
        for (int i = 0; i < n; i++) {
            streams[i] = client.get(host, "/hello");
        }
        for (int i = 0; i < n; i++) {
            SpdyClient.checkResponse(streams[i]);
        }

    }

    @Test
    public void testGet10() throws Exception {
        for (int i = 0; i < 10; i++) {
            get();
        }
    }

    @Test
    public void testGet10P() throws Exception {
        getNParallel(10);
    }

    @Test
    public void testGet100() throws Exception {
        for (int i = 0; i < 100; i++) {
            get();
        }
    }

    @Test
    public void testGet100P() throws Exception {
        getNParallel(100);
    }

}
