/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.HashMap;

/**
 * Client side implementation of SPDY protocol.
 * 
 * The base class supports the internal variant - no SSL, no compression.
 * 
 * Use SpdyClientApr for the external protocol - requires installing the 
 * jni library.
 * 
 * This class represents a single persistent SPDY connection. The connection
 * will be re-established as needed, and kept alive.
 */
public class SpdyClient {
    protected SpdyContext spdyCtx = new SpdyContext();
    protected SpdyFramer spdy;
    
    String host; 
    int port;
    
    boolean insecureCerts = true;
    
    
    public SpdyClient() {
    	init();
    }
    	
    public void init() {
    	spdy = new SpdyFramerJioSocket(spdyCtx, host, port);
    }
    
    public ClientSpdyStream get(String url) throws IOException {
        ClientSpdyStream sch = new ClientSpdyStream(spdy);
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
        client.setTarget(host, port);
        
        client.get(url);
        
        
    }

    public void setTarget(String host, int port) {
        this.host = host;
        this.port = port;
    }

    boolean connecting;
    boolean connected;

    
    /** 
     * Default implementation.
     */
    public class SpdyFramerJioSocket extends SpdyFramer {
        Socket socket;
        Runnable inputThread = new Runnable() {
			@Override
			public void run() {
                onBlockingSocket();
                try {
					socket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
        };

        public SpdyFramerJioSocket(SpdyContext spdyContext, 
                String host, int port) {
            super(spdyContext);
        } 
        
        protected boolean checkConnection(SpdyFrame oframe) throws IOException {
        	if (connected) {
        		return true;
        	}
            if (connecting) {
                return false;
            }
            connecting = true;
            try {
                Socket sock = new Socket(host, port);
                
                sock.getInputStream();
                connected = true;
                
                socket = sock;
                
                spdyCtx.getExecutor().execute(inputThread);

                return true;
            } catch (IOException ex) {
            	ex.printStackTrace();
                connecting = false;
            }
            
            return true;
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
    

    public static class ClientSpdyStream extends SpdyStream {
        public static final Charset UTF8 = Charset.forName("UTF-8");
        HashMap<String, String> resHeaders = new HashMap<String, String>();
        
        public ClientSpdyStream(SpdyFramer spdy) {
            this.spdy = spdy;
            reqFrame = spdy.getFrame(SpdyFramer.TYPE_SYN_STREAM);
        }

        @Override
        public void onCtlFrame(SpdyFrame frame) throws IOException {
            // TODO: handle RST
            resFrame = frame;
            processHeaders(resFrame);
            if (resFrame.isHalfClose()) {
                finRcvd = true;
            }
        }
        
        public void processHeaders(SpdyFrame f) {
            int nvCount = f.nvCount;
            for (int i = 0; i < nvCount; i++) {
                int len = f.read16();
                String n = new String(f.data, f.off, len, UTF8);
                f.advance(len);
                len = f.read16();
                String v = new String(f.data, f.off, len, UTF8);
                f.advance(len);
                resHeaders.put(n,  v);
            }
        }
        
        public void addHeader(String name, String value) {
            byte[] nameB = name.getBytes();
            reqFrame.headerName(nameB, 0, nameB.length);
            nameB = value.getBytes();
            reqFrame.headerValue(nameB, 0, nameB.length);
        }
        
        
        public void send() throws IOException {
        	send("http", "GET");
        }
        
        public void send(String scheme, String method) throws IOException {
        	if ("GET".equalsIgnoreCase(method)) {
                // TODO: add the others
                reqFrame.halfClose();        		
        	}
            addHeader("scheme", "http"); // todo
            addHeader("method", method);
            addHeader("version", "HTTP/1.1");
            if (reqFrame.isHalfClose()) {
                finSent = true;
            }
            spdy.sendFrameBlocking(reqFrame, this);
        }
    }    
    
}
