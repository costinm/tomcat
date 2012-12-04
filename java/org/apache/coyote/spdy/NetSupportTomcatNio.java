/*
 */
package org.apache.coyote.spdy;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;
import java.util.List;

import javax.net.ssl.SSLEngine;

import org.apache.tomcat.spdy.SpdyConnection;
import org.apache.tomcat.spdy.SpdyContext;
import org.apache.tomcat.util.net.NioChannel;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.NioSelectorPool;
import org.apache.tomcat.util.net.SecureNioChannel;
import org.apache.tomcat.util.net.SocketWrapper;
import org.eclipse.jetty.npn.NextProtoNego;

/**
 * Implementation of SpdyContext.NetSupport for coyote NIO
 * 
 */
public class NetSupportTomcatNio extends SpdyContext.NetSupport {
    /**
     * Selector pool, for blocking reads and blocking writes
     */
    public NioSelectorPool pool;

    private final class SpdyNpnProvider implements NextProtoNego.ServerProvider {
        String selected;
        
        @Override
        public void unsupported() {
            System.out.println("Unsupported");
        }

        @Override
        public List<String> protocols() {
            System.out.println("Send protocols");
            return npnSupportedList;
        }

        @Override
        public void protocolSelected(String protocol) {
            selected = protocol;
        }
    }

    /** 
     * Not supported in client mode 
     */
    @Override
    public SpdyConnection getConnection(String host, int port)
            throws IOException {
        return null;
    }

    @Override
    public void onCreateEngine(Object engine) {
        NextProtoNego.debug = true;
        NextProtoNego.put((SSLEngine) engine, new SpdyNpnProvider());
    }

    @Override
    public String getNpn(Object channel) {
        if (channel instanceof SecureNioChannel) {
            SpdyNpnProvider provider = (SpdyNpnProvider) NextProtoNego.get(((SecureNioChannel) channel).getSslEngine());
            return provider.selected;
        }
        return null;
    }

    @Override
    public void onAccept(Object socket, String proto) {
        SpdyConnectionChannel ch = new SpdyConnectionChannel(ctx, (SocketWrapper<NioChannel>) socket, proto);
        ch.pool = pool;
        ch.onBlockingSocket();                
    }

    public static class SpdyConnectionChannel extends SpdyConnection {
        SecureNioChannel socket;

        public NioSelectorPool pool;


        Runnable inputThread = new Runnable() {
            @Override
            public void run() {
                onBlockingSocket();
                try {
                    inClosed = true;
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };

        public SpdyConnectionChannel(SpdyContext spdyContext, SocketWrapper<NioChannel> socket,
                                     String proto) {
            super(spdyContext, proto);
            this.socket = (SecureNioChannel) socket.getSocket();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }

        @Override
        public synchronized int write(byte[] data, int off, int len) throws IOException {
            ByteBuffer writeBuffer = socket.getBufHandler().getWriteBuffer();
            writeBuffer.clear();
            writeBuffer.put(data, off, len);
            writeToSocket(writeBuffer, true, true);
            writeBuffer.clear();
            return len;
        }

        private synchronized int writeToSocket(ByteBuffer bytebuffer, boolean block, boolean flip)
                throws IOException {
            if ( flip ) bytebuffer.flip();

            int written = 0;
            NioEndpoint.KeyAttachment att = (NioEndpoint.KeyAttachment)socket.getAttachment(false);
            if ( att == null ) throw new IOException("Key must be cancelled");
            long writeTimeout = att.getTimeout();
            Selector selector = null;
            try {
                selector = pool.get();
            } catch ( IOException x ) {
                //ignore
            }
            try {
                written = pool.write(bytebuffer, socket, selector, writeTimeout, block);
                //make sure we are flushed
                do {
                    if (socket.flush(true,selector,writeTimeout)) break;
                } while ( true );
            }finally {
                if ( selector != null ) pool.put(selector);
            }
            if ( block ) bytebuffer.clear(); //only clear
            return written;
        }

        /**
         * Perform blocking read with a timeout if desired
         * 
         * Data is written to the socket's read buffer.
         * 
         * @param timeout boolean - if we want to use the timeout data
         * @param block - true if the system should perform a blocking read, false otherwise
         * @return boolean - true if data was read, false is no data read, EOFException if EOF is reached
         * @throws IOException if a socket exception occurs
         * @throws EOFException if end of stream is reached
         */
        private int readSocket(boolean timeout, boolean block) throws IOException {

            int nRead = 0;
            socket.getBufHandler().getReadBuffer().clear();
            if ( block ) {
                Selector selector = null;
                try {
                    selector = pool.get();
                } catch ( IOException x ) {
                    // Ignore
                }
                try {
                    NioEndpoint.KeyAttachment att = (NioEndpoint.KeyAttachment)socket.getAttachment(false);
                    if ( att == null ) throw new IOException("Key must be cancelled.");
                    nRead = pool.read(socket.getBufHandler().getReadBuffer(),socket,selector,att.getTimeout());
                } catch ( EOFException eof ) {
                    nRead = -1;
                } finally {
                    if ( selector != null ) pool.put(selector);
                }
            } else {
                nRead = socket.read(socket.getBufHandler().getReadBuffer());
            }
            return nRead;
        }
        
        ByteBuffer readBuffer = null;
        
        @Override
        public int read(byte[] data, int off, int len) throws IOException {
            try {
                if (readBuffer != null && readBuffer.remaining() > 0) {
                    int toRead = Math.min(len, readBuffer.remaining());
                    System.err.println("RD: " + off + " " + len + " " + toRead + " " + data.length);
                    readBuffer.get(data, off, toRead);
                    return toRead;
                }
                // readBuffer is empty
                int rd = readSocket(true, true);
                
                readBuffer = socket.getBufHandler().getReadBuffer();
                
                if (rd > 0) {
                    readBuffer.flip(); // only first time, after read
                    int toRead = Math.min(len, readBuffer.remaining());
                    readBuffer.get(data, off, toRead);
                    return toRead;
                }
                return rd;
            } catch (IOException ex) {
                return 0;
            }
        }
    }

    /** 
     * Not supported in standalone mode
     */
    @Override
    public void listen(int port, String cert, String key) throws IOException {
    }


    @Override
    public void stop() throws IOException {
    }


}
