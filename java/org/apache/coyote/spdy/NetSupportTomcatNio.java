/*
 */
package org.apache.coyote.spdy;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;
import java.util.Arrays;
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


public class NetSupportTomcatNio extends SpdyContext.NetSupport {

    List<String> protos = Arrays.asList(new String[] {"spdy/2", "http/1.1"});

    /**
     * Selector pool, for blocking reads and blocking writes
     */
    public NioSelectorPool pool;

    private final class SpdyNpnProvider implements NextProtoNego.ServerProvider {
        String selected;
        
        @Override
        public void unsupported() {
        }

        @Override
        public List<String> protocols() {
            return protos;
        }

        @Override
        public void protocolSelected(String protocol) {
            selected = protocol;
        }
    }

    @Override
    public SpdyConnection getConnection(String host, int port)
            throws IOException {
        return null;
    }


    public void onCreateEngine(Object engine) {
        NextProtoNego.debug = true;
        NextProtoNego.put((SSLEngine) engine, new SpdyNpnProvider());
    }
    
    public boolean isSpdy(Object channel) {
        if (channel instanceof SecureNioChannel) {
            SpdyNpnProvider provider = (SpdyNpnProvider) NextProtoNego.get(((SecureNioChannel) channel).getSslEngine());
            if ("spdy/2".equals(provider.selected)) {
                return true;
            }            
        }
        return false;
    }

    public void onAccept(Object socket) {
        SpdyConnectionChannel ch = new SpdyConnectionChannel(ctx, (SocketWrapper<NioChannel>) socket);
        ch.pool = pool;
        ch.onBlockingSocket();                
    }

    public static class SpdyConnectionChannel extends SpdyConnection {
        SecureNioChannel socket;

//        private KeyAttachment socketW;

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

        public SpdyConnectionChannel(SpdyContext spdyContext) {
            super(spdyContext);
        }

        public SpdyConnectionChannel(SpdyContext spdyContext, SocketWrapper<NioChannel> socket) {
            super(spdyContext);
            this.socket = (SecureNioChannel) socket.getSocket();
//            this.socketW = socket;
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

        private synchronized int writeToSocket(ByteBuffer bytebuffer, boolean block, boolean flip) throws IOException {
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
                }while ( true );
            }finally {
                if ( selector != null ) pool.put(selector);
            }
            if ( block ) bytebuffer.clear(); //only clear
            return written;
        }

        /**
         * Perform blocking read with a timeout if desired
         * @param timeout boolean - if we want to use the timeout data
         * @param block - true if the system should perform a blocking read, false otherwise
         * @return boolean - true if data was read, false is no data read, EOFException if EOF is reached
         * @throws IOException if a socket exception occurs
         * @throws EOFException if end of stream is reached
         */

        private int readSocket(boolean timeout, boolean block,
                byte[] buf, int pos, int len) throws IOException {

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
            if (nRead > 0) {
                socket.getBufHandler().getReadBuffer().flip();
                socket.getBufHandler().getReadBuffer().limit(nRead);
                //expand(nRead + pos);
                socket.getBufHandler().getReadBuffer().get(buf, pos, nRead);
                //lastValid = pos + nRead;
                return nRead;
            } else if (nRead == -1) {
                //return false;
                return nRead;
            } else {
                return 0;
            }
        }


        
        @Override
        public int read(byte[] data, int off, int len) throws IOException {
            try {
                ByteBuffer readBuffer = socket.getBufHandler().getReadBuffer();
                int rd = readSocket(true, true, data, off, len);
                if (rd > 0) {
                    readBuffer.flip();
                    System.arraycopy(readBuffer.array(), readBuffer.position() + readBuffer.arrayOffset(), 
                            data, off, len);
                }
                return rd;
            } catch (SocketTimeoutException ex) {
                return 0;
            }
        }
    }


}
