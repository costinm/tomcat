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
        if ("org.apache.coyote.spdy.SpdyProxyProtocol".equals(protocol)) {
            spdyCtx = new SpdyContextProxy();
        } else if ("org.apache.coyote.http11.Http11AprProtocol"
                .equals(protocol)) {
            connector.setProperty("npnHandler", 
                    "org.apache.coyote.spdy.SpdyAprNpnHandler");
            
            spdyCtx = new SpdyContextJni();
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
        SpdyStream stream = client.get(host, "/hello");
        SpdyFrame f;
        int dataLen = 0;
        while ((f = stream.getDataFrame(to)) != null) {
            dataLen += f.getDataSize();
        }
        HashMap<String, String> resHeaders = new HashMap<String, String>();
        stream.getResponse().getHeaders(resHeaders);        
        assertEquals(resHeaders.get("status"), "200 OK");
        assertEquals(dataLen,
                Integer.parseInt(resHeaders.get("content-length")));

    }

    int to = 20000;

    public void getNParallel(int n) throws IOException {
        SpdyStream[] streams = new SpdyStream[n];
        for (int i = 0; i < n; i++) {
            streams[i] = client.get(host, "/hello");
        }
        for (int i = 0; i < n; i++) {
            SpdyFrame f;
            int dataLen = 0;
            while ((f = streams[i].getDataFrame(to)) != null) {
                dataLen += f.getDataSize();
            }
            HashMap<String, String> resHeaders = new HashMap<String, String>();
            streams[i].getResponse().getHeaders(resHeaders);
            assertEquals(resHeaders.get("status"), "200 OK");
            assertEquals(dataLen, Integer.parseInt(resHeaders
                    .get("content-length")));
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
