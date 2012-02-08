/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.net.Socket;

/**
 * Client side implementation of SPDY protocol.
 * 
 * The base class supports the 'intranet' variant - no SSL, no compression.
 * 
 * Use SpdyClientApr for the external protocol - requires installing the 
 * jni library.
 * 
 * This class represents a single persistent SPDY connection. The connection
 * will be re-established as needed, and kept alive.
 */
public class SpdyClient implements Runnable {
    protected SpdyContext spdyCtx = new SpdyContext();
    protected SpdyFramer spdy;
    
    String host; 
    int port;
    
    boolean insecureCerts = true;
    
    
    public SpdyClient() {
    }
    
    public void init() {
        spdy = new SpdyFramerJioSocket(spdyCtx, host, port);
        new Thread(this).start();
    }
    
    public void run() {
        try {
            ((SpdyFramerJioSocket) spdy).connect();
        } catch (IOException ex) {
            // Channel closed, no longer running
        }
    }
    
    public SimpleSpdyStream get(String url) throws IOException {
        SimpleSpdyStream sch = new SimpleSpdyStream(spdy);
        sch.addHeader("host", host);
        sch.addHeader("url", url);
        
        sch.send();
        
        return sch;
    }
    
    public static void main(String args[]) throws IOException {
        if (args.length == 0) {
            args = new String[] {"www.google.com", "443", "/"};
        }
        // TODO: CLI parsing
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String url = args[2];
        
        SpdyClient client = new SpdyClient();
        client.init();
        client.setTarget(host, port);
        
        client.get(url);
        
        
    }

    public void setTarget(String host, int port) {
        this.host = host;
        this.port = port;
    }

    /** 
     * Default implementation.
     */
    public static class SpdyFramerJioSocket extends SpdyFramer {
        Socket socket;
        private String host;
        private int port;

        public SpdyFramerJioSocket(SpdyContext spdyContext, 
                String host, int port) {
            super(spdyContext);
            this.host = host;
            this.port = port;
        } 
        
        public void connect() throws IOException {
            Socket sock = new Socket(host, port);
            
            sock.getInputStream();
            
            socket = sock;
            onData();

            sock.close();
        }

        @Override
        public int write(byte[] data, int off, int len) throws IOException {
            socket.getOutputStream().write(data, off, len);
            return len;
        }

        @Override
        public int read(byte[] data, int off, int len) throws IOException {
            return socket.getInputStream().read(data, off, len);
        }
    }
    
    
}
