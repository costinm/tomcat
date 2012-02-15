/*
 */
package org.apache.tomcat.spdy;

import static org.junit.Assert.*;

import java.io.IOException;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.spdy.SpdyClient.ClientSpdyStream;
import org.apache.tomcat.util.net.TesterSupport;
import org.junit.Before;
import org.junit.Test;

public class TomcatSpdyTest extends TomcatBaseTest {

    boolean realSpdy = false;

    SpdyClient client;

    protected void extraConnectorSetup(Connector connector, String protocol) {
        if ("org.apache.coyote.http11.Http11Protocol".equals(protocol)) {
//            connector.setProperty("lightProtocol",
//                    "org.apache.tomcat.spdy.SpdyTomcatJioProtocol");
            connector.setProperty("lightHandler",
                    "org.apache.tomcat.spdy.TomcatJioHandler");
            client = new SpdyClient();

        } else if ("org.apache.coyote.http11.Http11AprProtocol"
                .equals(protocol)) {
            connector.setProperty("lightHandler",
                    "org.apache.tomcat.spdy.TomcatAprHandler");
//            connector.setProperty("lightProtocol",
//                    "org.apache.tomcat.spdy.SpdyTomcatAprProtocol");
            client = new SpdyClientApr();
            realSpdy = true;
            Tomcat tomcat = getTomcatInstance();
            TesterSupport.initSsl(tomcat);
        }
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
        client.setTarget("localhost", getPort());
    }

    @Test
    public void testGet1() throws Exception {
        get();
    }

    public void get() throws IOException {
        SpdyClient.ClientSpdyStream stream = client.get("/hello");
        SpdyFrame f;
        int dataLen = 0;
        while ((f = stream.getIn(to)) != null) {
            dataLen += f.getDataSize();
        }
        assertEquals(stream.resHeaders.get("status"), "200 OK");
        assertEquals(dataLen,
                Integer.parseInt(stream.resHeaders.get("content-length")));

    }

    int to = 20000;

    public void getNParallel(int n) throws IOException {
        ClientSpdyStream[] streams = new ClientSpdyStream[n];
        for (int i = 0; i < n; i++) {
            streams[i] = client.get("/hello");
        }
        for (int i = 0; i < n; i++) {
            SpdyFrame f;
            int dataLen = 0;
            while ((f = streams[i].getIn(to)) != null) {
                dataLen += f.getDataSize();
            }
            assertEquals(streams[i].resHeaders.get("status"), "200 OK");
            assertEquals(dataLen, Integer.parseInt(streams[i].resHeaders
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
