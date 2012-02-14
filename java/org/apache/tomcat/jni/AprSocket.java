/*
 */
package org.apache.tomcat.jni;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

import org.apache.tomcat.jni.AprSocketContext.AprPoller;
import org.apache.tomcat.jni.AprSocketContext.HostInfo;

public class AprSocket {
    
    /**
     * Channel events. The methods may be called from an IO thread,
     * so they should never block.
     */
    public interface AsyncHandler {
        
        /** 
         * Called on IO events: data available, connection established (called
         * after ssl handshake), input closed. 
         * 
         * This may be called for multiple reasons - for example the io thread
         * may accept a connection, read the data and close the input, than
         * call handleIO() once. 
         * @param last last notification, just before the socket is destroyed
         */
        public void handleIO(AprSocket ch, boolean last) 
                throws IOException;
    }
    
    public static final byte[][] NO_CERTS = new byte[0][];
    
    static Logger log = Logger.getLogger("AprChannel");
    static AtomicInteger handshakeTimeouts = new AtomicInteger();
    static AtomicInteger handshakeErrors = new AtomicInteger();
    static AtomicInteger handshakeOk = new AtomicInteger();
    static AtomicInteger channelCnt = new AtomicInteger();
    
    AprSocketContext factory;

    // only one - to save per/socket memory - context has similar callbacks.
    AsyncHandler ioListeners;
    
    private Lock channelLock = new ReentrantLock();
    private Condition ioCondition;

    long socket;

    AprPoller poller;
    // True if we need writeable notification
    boolean pollOut = false;
    
    // Protected by pollerLock. If true it is in pollset
    boolean pollIn = false;


    boolean connecting = false; // to prevent 2 calls to connect
    protected boolean connected = false;
    
    protected boolean outClosed;
    protected boolean inClosed;
    
    // used for blocking. TODO: use in non-blocking as well
    protected long ioTimeout = 10000; // ms
    
    // Last activity timestamp.
    public long ts;
    
    // Persistent info about the peer ( SSL, etc )
    protected HostInfo peerInfo;
    
    boolean secure = false;
    boolean sslAttached = false;
    
    // From IOChannel
    // Fush has been called and it's not yet done.
    protected boolean flushing = false;

    
    protected String errorMessage;
    
    /**
     * A string that can be parsed to extract the target.
     * host:port for normal sockets
     */
    protected String target;
    protected String remoteHost;
    protected int remotePort;


    protected String remoteAddress;
    protected String localHost;
    protected String localAddress;
    protected int localPort;

    private boolean blocking = true;

    public void recycle() {
        pollOut = false;
        pollIn = false;
        sslAttached = false;
        connecting = false;
        flushing = false;
        connected = false;
        secure = false;
        peerInfo = null;
        ts = 0;
        ioListeners = null;
        outClosed = false;
        errorMessage = null;
        ioTimeout = 10000;
        target = null;
        remoteHost = null;
        remotePort = 0;
        
        // channelNum remains
        // connector remains
        socket = 0;
        poller = null;
        remoteAddress = null;
        localAddress = null;
        localPort = 0;
        
    }
    
    
    public AprSocket() {
        ioCondition = channelLock.newCondition();
    }
    
    public boolean isOpen() {
        return ! inClosed; // as soon as EOF is received, socket is reset
    }
        
    public String getTarget() {
        return target;
    }
    
    public AprSocket setTarget(String host, int port) {
        target = host + ":" + port;
        remotePort = port;
        remoteHost = host;
        return this;
    }

    public AprSocket setTarget(String target) {
        this.target = target;
        String[] comp = target.split(":");
        if (comp.length > 1) {
            remotePort = Integer.parseInt(comp[1]);
        }
        remoteHost = comp[0];
        return this;
    }

    public String errorMessage() {
        return errorMessage;
    }
    
    /**
     * Close input and output, potentially sending RST, than close the socket.
     */
    public void error(String err) {
        errorMessage = err;
        log.warning("ERR: " + socket + " " + err);
        try {
            close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void error(Throwable exception) {
        if (exception != null) {
            exception.printStackTrace();
        }
        
        error(exception.getMessage());
    }
    
    public long getIOTimeout() {
        return ioTimeout;
    }
    
    public void setIOTimeout(long timeout) {
        ioTimeout = timeout;
        if (socket != 0) {
            Socket.timeoutSet(socket, ioTimeout * 1000);
        }
    }
    
    void notifyIO(int received, boolean closed) 
            throws IOException {
        ts = System.currentTimeMillis();
        try {
            channelLock.lock();
            try {
                ioCondition.signalAll();
            } finally {
                channelLock.unlock();
            }
            if (ioListeners != null) {
                ioListeners.handleIO(this, false);
            }
        } catch (Throwable t) {
            t.printStackTrace();
            try {
                close();
            } catch(Throwable t2) {
                t2.printStackTrace();
            }
            if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(t);
            }
        } 
    }
    
    public void addIOHandler(AsyncHandler l) {
        if (l == null) {
            return;
        }
        if (outClosed) {
            // was closed - we didn't add it, just notify of end
            try {
                notifyIO(0, true);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
//            // Make sure close was called
//            channelLock.lock();
//            try {
//                ioListeners.add(l);
//            } finally {
//                channelLock.unlock();
//            }
            ioListeners = l;
        }
    }

    public void halfClose() throws IOException {
        // TODO 
        // just send FIN
    }
    
    /**
     */
    public void close() throws IOException {
        channelLock.lock();
        try {
            inClosed = true;
            if (outClosed) {
                return;
            }
            outClosed = true; // and send the events
        } finally {
            channelLock.unlock();
        }
        
        
        // Should send a FIN at the end. 
        // exceptions / abort should send RST - i.e. no 
        // flush before close()

        notifyIO(0, true);
        if (factory.debug) {
            log.info("Closing " + this);
        }
        poll(false);
    }
    
    public AprSocketContext getFactory() {
        return factory;
    }

    public void setBlocking(boolean block) {
        this.blocking = block;
        if (socket != 0) {
            if (block) {
                Socket.optSet(socket, Socket.APR_SO_NONBLOCK, 0);            
            } else {
                Socket.optSet(socket, Socket.APR_SO_NONBLOCK, 1);
            }
        }
    }
    
    /** 
     * Non-blocking connect method
     */
    public void connect() throws IOException {
    	if (blocking) {
    		factory.connectBlocking(this, remoteHost, remotePort);
    		// will call handleConnected() at the end.
    	} else {
	        channelLock.lock();
	        try {
	            if (connecting) {
	                return;
	            }
	            connecting = true;
	        } finally { channelLock.unlock(); }
	        
	        factory.connect(this, remoteHost, remotePort);
    	}
    }
    

    // after connection is done, called from a thread pool ( not IO thread )
    // may block for handshake.
    void handleConnected() throws IOException {
        if (secure) {
            blockingStartTLS(); 
        }
        
        Socket.timeoutSet(socket, ioTimeout * 1000);

        connected = true;
        
        notifyIO(0, false);
    }
    
    
    public void readInterest(boolean b) throws IOException {
        if (b && !inClosed) {
            ((AprSocketContext) getFactory()).updatePolling(this);
        } else {
            // TODO: stop reading
        }
    }


    public HostInfo getPeerInfo() {
        if (peerInfo == null) {
            peerInfo = factory.getPeerInfo(target);
        }  
        return peerInfo;
    }
    
    public X509Certificate[] getPeerX509Cert() throws IOException {
        byte[][] certs = getPeerCert(false);
        X509Certificate[] xcerts = new X509Certificate[certs.length];
        if (certs.length == 0) {
            return xcerts;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (int i = 0; i < certs.length; i++) {
                if (certs[i] != null) {
                    ByteArrayInputStream bis = new ByteArrayInputStream(certs[i]);
                    xcerts[i] = (X509Certificate) cf.generateCertificate(bis);
                    bis.close();
                }
            }    
        } catch (CertificateException ex) {
            throw new IOException(ex);
        }
        return xcerts;
    }
    
    public String toString() {
        return "AprCh-" + 
        Long.toHexString(socket) + 
        (connected? " C": "") + 
        (flushing ? " F": "") + 
        (pollOut ? " PO" : "") +
        (inClosed ? " CL-I": "") +
        (outClosed ? " CL-O": "");
    }


    protected void poll(boolean enabled) {
        if (!enabled) {
            if (poller != null) {
                poller.updatePolling(this, false);
            }
        }
    }
    
    private boolean waitConnect() throws IOException {
        long now = System.currentTimeMillis();
        long end = now + ioTimeout;

        while (true) {
            channelLock.lock();
            try {
                if (connected) {
                    return true;
                }
                if (inClosed) {
                    return false;
                }
                
                if (System.currentTimeMillis() > end) {
                    throw new IOException("Deadline exceeded");
                }
                
                ioCondition.await(100, TimeUnit.MILLISECONDS);
                System.err.println("Connected: " + connected);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } finally {
                channelLock.unlock();
            }
        }
    }

    public int write(byte[] data, int off, int len) throws IOException {
        if (!connected) {
            connect();
            if (blocking) {
                waitConnect();
            } else {
                pollOut = true; // will call write notifications when connected
                return 0;
            }
        }
        if (outClosed || socket == 0) {
        	return -1;
        }
        int sent = Socket.send(socket, data, off, len); 
        
        if (sent == -Status.TIMEUP) {
            if (factory.debug) {
                log.info("apr.send TIMEUP");
            }
            return 0;
        } else if (sent == -Status.EAGAIN) {
            pollOut = true;
            //log.warning("apr.send(): EAGAIN, polling ");
            ((AprSocketContext) factory).updatePolling(this);
            
            return 0;
        }
        if (sent < 0) {
            if (factory.debug) {
                log.warning("apr.send(): Failed to send, closing socket " + sent);
            }
            error("Error sending " + sent + " " + Error.strerror((int)-sent));
            return sent;
        } else {
            if (sent > 0) {
                factory.rawData(this, false, data, off, sent, false);
            } 
            if (sent < len) {
                if (factory.debug) {
                    log.warning("apr.send(): Incomplete send, poll out");
                }
                pollOut = true;
                ((AprSocketContext) factory).updatePolling(this);
            }
            return sent;
        }
    }
    
    public int read(byte[] data, int off, int len) throws IOException {
        if (!connected) {
            connect();
            if (blocking) {
                waitConnect();
            } else {
                pollIn = true; // will call write notifications when connected
                return 0;
            }
            return 0;
        }
        if (socket == 0 || inClosed) {
        	return -1;
        }
        int read = Socket.recv(socket, data, off, len);

        if (read == -Status.TIMEUP) {
            read = 0;
        }
        if (read == -Status.EAGAIN) {
            read = 0;
        }
        if (read == - Status.APR_EOF) {
        	pollIn = false;
        	log.info("apr.read(): EOF" + socket);
        	inClosed = true;
            factory.rawData(this, true, null, 0, read, true);
        	return -1;
        } 
        if (read < 0){
        	pollIn = false;
        	String msg = socket + " apr.read(): " + read + " " +
        			Error.strerror((int)-read);
        	log.info(msg);
        	if (secure) {
        		log.info("SSL: " + " " + SSL.getLastError());
        	}
        	error(msg);
        	return read;
        }
        if (factory.debug) log.info(socket + " apr.read(): " + read);
        factory.rawData(this, true, null, 0, read, false);
        
        return read;
    }
    
    
    public boolean isOutClosed() {
        return outClosed;
    }
    
    private void shutdownOutput() throws IOException {
        // After flush: FIN
        // if data has not been fully flushed: RST
        if (socket != 0) {
            Socket.shutdown(socket, Socket.APR_SHUTDOWN_WRITE);
        }
    }
    
    // Cert is in DER format
    // Called after handshake
    public byte[][] getPeerCert(boolean check) throws IOException {
        getPeerInfo();
        if (peerInfo.certs != null && peerInfo.certs != NO_CERTS && 
                !check) {
            return peerInfo.certs;
        }
        if (!secure || socket == 0) {
            return NO_CERTS;
        }
        try {
            int certLength = SSLSocket.getInfoI(socket, 
                    SSL.SSL_INFO_CLIENT_CERT_CHAIN);
            // TODO: if resumed, old certs are good.
            // If not - warn if certs changed, remember first cert, etc.
            if (certLength <= 0) {
                // Can also happen on session resume - keep the old
                if (peerInfo.certs == null) {
                    peerInfo.certs = NO_CERTS;
                }
                return peerInfo.certs;
            }
            peerInfo.certs = new byte[certLength + 1][];
            
            peerInfo.certs[0] = SSLSocket.getInfoB(socket, SSL.SSL_INFO_CLIENT_CERT);
            for (int i = 0; i < certLength; i++) {
                peerInfo.certs[i + 1] = SSLSocket.getInfoB(socket, 
                        SSL.SSL_INFO_CLIENT_CERT_CHAIN + i);
            }
            return peerInfo.certs;
        } catch (Exception e) {
            throw new IOException(e);
        }        
    }
    
    
    public String getCipherSuite() throws IOException {
        if (!secure  || socket == 0) {
            return null;
        }
        try {
            return SSLSocket.getInfoS(socket, SSL.SSL_INFO_CIPHER);
        } catch (Exception e) {
            throw new IOException(e);
        }        
    }

    public int getKeySize() throws IOException {
        if (!secure || socket == 0) {
            return -1;
        }
        try {
            return SSLSocket.getInfoI(socket, SSL.SSL_INFO_CIPHER_USEKEYSIZE);
        } catch (Exception e) {
            throw new IOException(e);
        }        
    }

    public void setSecure() {
        secure = true;
    }
    
    /** 
     * This is a blocking call !
     * ( can be made non-blocking, but too complex )
     * 
     * Will be called automatically after connect() or accept if 'secure'
     * is true.
     * 
     * Can be called manually to upgrade the channel
     */
    public void blockingStartTLS() {
        secure = true; // will be done at connect
        channelLock.lock();
        if (socket == 0) {
            return;
        }
        try {
            if (sslAttached) {
                return;
            }
            if (factory.debug) {
                log.info(this + " StartSSL");
            }
        
            AprSocketContext aprCon = (AprSocketContext) factory;
            SSLSocket.attach(aprCon.getSslCtx(), socket);
            sslAttached = true;
            
            if (factory.debug) {// & !((AprChannelFactory) getFactory()).isServerMode()) {
                SSLExt.debug(socket);
            }
            if (!((AprSocketContext) getFactory()).isServerMode()) {
                getPeerInfo();

                // use ticket if possible
//                if (peerInfo.ticketLen > 0) {
//                    SSLExt.setTicket(socket, peerInfo.ticket, 
//                            peerInfo.ticketLen);
//                } else 
                if (peerInfo.sessDer != null) {
                    // both ticket and session data ( secret, etc ) must be
                    // saved. Session Data includes the ticket !
                    SSLExt.setSessionData(socket, peerInfo.sessDer, 
                            peerInfo.sessDer.length);
                }
            }
            
            continueHandshake();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            channelLock.unlock();
        }
    }
    
    /** 
     * Called from read/write, if ssl mode and the handshake is not 
     * completed
     * 
     * @return true if done.
     */
    boolean continueHandshake() throws IOException {
        channelLock.lock();
        try {
            int rc = SSLSocket.handshake(socket);
            if (factory.debug) {
                log.info(this + " ContinueHandshake " + rc);
            }

            if (rc == Status.APR_TIMEUP) {
                if (factory.debug) {
                    log.info("Timeout in handshake, will continue");
                }
                // will continue.
                handshakeTimeouts.incrementAndGet();
                try {
                    log.severe(this + " Handshake failed " + 
                            rc + " " + Error.strerror(rc) + " SSLL " + SSL.getLastError());
                    error("Handshake failed");
                    close();
                    return false;
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    return false;
                }
            } else if (rc != Status.APR_SUCCESS) {
                handshakeErrors.incrementAndGet();
                try {
                    log.severe(this + " Handshake failed " + 
                            rc + " " + Error.strerror(rc) + " SSLL " + SSL.getLastError());
                    error("Handshake failed");
                    close();
                    return false;
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    return false;
                }
            } else { // SUCCESS
                if (factory.debug) {
                    log.info("Handshake OK " + this);
                }
                handshakeOk.incrementAndGet();
                handshakeDone();
                return true;
            }
        } finally {
            channelLock.unlock();
        }
    }
    
    protected void handshakeDone() throws IOException {
        getPeerInfo();
        if (socket == 0) {
        	throw new IOException("Socket closed");
        }
        peerInfo.sessDer = SSLExt.getSessionData(socket);

        // TODO: if the ticket changed - save the session again
        // TODO: if session ID changed - save the session again
            
//        if (!((AprConnector) getFactory()).isServerMode()) {
//            if (peerInfo.ticket == null) {
//                peerInfo.ticket = new byte[2048];
//            }
//            int ticketLen = SSLExt.getTicket(socket, peerInfo.ticket);
//            if (ticketLen > 0) {
//                peerInfo.ticketLen = ticketLen;
//                if (debug) {
//                    log.info("Received ticket: " + ticketLen);
//                }
//            }
//        }

        // Last part of handshake ok - send and receive any 
        // outstanding data.

        // will go away if shutdown is received, or on resume
        getPeerCert(true); 


        try {
            peerInfo.sessionId = SSLSocket.getInfoS(socket, 
                    SSL.SSL_INFO_SESSION_ID);
        } catch (Exception e) {
            throw new IOException(e);
        }

        peerInfo.npn = new byte[32];
        peerInfo.npnLen = SSLExt.getNPN(socket, peerInfo.npn);
        
        // If custom verification is used
        factory.notifyHandshakeDone(this);
    }    
    
    public int getRemotePort() {
        if (socket != 0 && remotePort == 0) {
            try {
                long sa = Address.get(Socket.APR_REMOTE, socket);
                Sockaddr addr = Address.getInfo(sa);
                remotePort = addr.port;
            } catch (Exception ex) {
            }
        }
        return remotePort;
    }

    public String getRemoteAddress() {
        if (socket != 0 && remoteAddress == null) {
            try {
                long sa = Address.get(Socket.APR_REMOTE, socket);
                remoteAddress = Address.getip(sa);
            } catch (Exception ex) {
            }
        }
        return remoteAddress;
    }

    public String getRemoteHostname() {
        if (socket != 0 && remoteHost == null) {
            try {
                long sa = Address.get(Socket.APR_REMOTE, socket);
                remoteHost = Address.getnameinfo(sa, 0);
                if (remoteHost == null) {
                    remoteHost = Address.getip(sa);
                }
            } catch (Exception ex) {
            }
        }
        return remoteHost;
    }

    public int getLocalPort() {
        if (socket != 0 && localPort == 0) {
            try {
                long sa = Address.get(Socket.APR_LOCAL, socket);
                Sockaddr addr = Address.getInfo(sa);
                localPort = addr.port;
            } catch (Exception ex) {
            }
        }
        return localPort;
    }

    public String getLocalAddress() {
        if (socket != 0 && localAddress == null) {
            try {
                long sa = Address.get(Socket.APR_LOCAL, socket);
                localAddress = Address.getip(sa);
            } catch (Exception ex) {
            }
        }
        return localAddress;
    }

    public String getLocalHostname() {
        if (socket != 0 && localHost == null) {
            try {
                long sa = Address.get(Socket.APR_LOCAL, socket);
                localHost = Address.getnameinfo(sa, 0);
            } catch (Exception ex) {
            }
        }
        return localHost;
    }
}