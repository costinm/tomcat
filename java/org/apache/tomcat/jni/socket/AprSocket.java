/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.jni.socket;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import org.apache.tomcat.jni.Address;
import org.apache.tomcat.jni.Error;
import org.apache.tomcat.jni.Poll;
import org.apache.tomcat.jni.SSL;
import org.apache.tomcat.jni.SSLExt;
import org.apache.tomcat.jni.SSLSocket;
import org.apache.tomcat.jni.Sockaddr;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;
import org.apache.tomcat.jni.socket.AprSocketContext.AprPoller;

public class AprSocket implements Runnable {

    static final byte[][] NO_CERTS = new byte[0][];

    static Logger log = Logger.getLogger("AprChannel");

    static int CONNECTING = 1;
    static int CONNECTED = 0x2;

    static int NONBLOCK = 0x4;
    
    static int IN_CLOSED = 0x10;
    static int OUT_CLOSED = 0x20;
    static int SSL_ATTACHED = 0x40;

    static int POLLIN = 0x80;
    static int POLLOUT = 0x100;

    static int ACCEPTED = 0x200;
    static int ERROR = 0x400;

    // Not null
    private AprSocketContext context;

    // only one - to save per/socket memory - context has similar callbacks.
    private AprSocketHandler handler;

    // Blocking: set when read polling. Accessed/modified from context.
    // Non-blocking: set unless 'suspendRead' and no write interest.
    // ( write interest is automatic ).
    AprPoller poller;
    
    // Bit field indicating the status and socket should only be accessed with 
    // socketLock protection
    private int status;
    
    long socket;

    // Persistent info about the peer ( SSL, etc )
    private HostInfo hostInfo;

    public void recycle() {
        status = 0;
        hostInfo = null;
        handler = null;
        socket = 0;
        poller = null;
    }

    AprSocket(AprSocketContext context) {
        this.context = context;
    }

    /**
     * Close the socket non-gracefully.
     */
    public void error(Throwable exception) {
        if (exception != null) {
            exception.printStackTrace();
        }

        error(exception.getMessage());
    }

    public void setIOTimeout(long timeout) throws IOException {
        if (socket != 0) {
            Socket.timeoutSet(socket, timeout * 1000);
        } else { 
            throw new IOException("Socket is closed");
        }
    }

    public long getIOTimeout() throws IOException {
        if (socket != 0) {
            try {
                return Socket.timeoutGet(socket) / 1000;
            } catch (Exception e) {
                throw new IOException(e);
            }
        } else { 
            throw new IOException("Socket is closed");
        }
    }

    void notifyIO(boolean needThread) throws IOException {
        long t0 = System.currentTimeMillis();
        try {
            if (handler != null) {
                if (!needThread) {
                    handler.process(this);
                    return;
                }
                if (isBlocking()) {
                    context.getExecutor().execute(this);
                } else {
                    // from IO thread, for a non blocking socket.
                    handler.process(this);                    
                }
            }
        } catch (Throwable t) {
            t.printStackTrace();
            error(t.getMessage());
            if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(t);
            }
        } finally {
            long t1 = System.currentTimeMillis();
            t1 -= t0;
            if (t1 > maxNotify.get()) {
                maxNotify.set(t1);
            }
        }
    }
    
    AtomicLong maxNotify = new AtomicLong();
    

    public void setHandler(AprSocketHandler l) {
        handler = l;
    }
    
    public AprSocketHandler getHandler() {
        return handler;
    }
    
    /**
     * For blocking: read poll.
     * For non-blocking: re-start polling after suspendRead()
     * 
     * @throws IOException
     */
    public void poll() throws IOException {
        if (handler == null) {
            throw new IOException("No callback");
        }
        context.poll(this);
    }

    /**
     * Suspend read events for non-blocking sockets.
     */
    public void suspendRead() throws IOException {
        if ((status & NONBLOCK) == 0) {
            throw new IOException("suspendRead() on blocking " + this);
        }
        clearStatus(POLLIN);
    }

    public void resumeRead() throws IOException {
        if ((status & NONBLOCK) == 0) {
            throw new IOException("resumeRead() on blocking " + this);
        }
        setStatus(POLLIN);
        poll();
    }

    public AprSocketContext getContext() {
        return context;
    }

    public void setNonBlocking() {
        setStatus(NONBLOCK);
        if (socket != 0) {
            Socket.optSet(socket, Socket.APR_SO_NONBLOCK, 1);
            Socket.timeoutSet(socket, 0);
        }
    }
    
    public void setBlocking(long ioTimeout) throws IOException {
        clearStatus(NONBLOCK);
        if (socket != 0) {
            Socket.optSet(socket, Socket.APR_SO_NONBLOCK, 0);
            Socket.timeoutSet(socket, ioTimeout * 1000);
        } else {
            throw new IOException("Not connected");
        }
    }

    AprSocket setHost(HostInfo hi) {
        hostInfo = hi;
        return this;
    }
     
    /**
     */
    public void connect() throws IOException {
        if ((status & NONBLOCK) == 0) {
            // will call handleConnected() at the end.
            context.connectBlocking(this);
        } else {
            synchronized(this) {
                if ((status & CONNECTING) != 0) {
                    return;
                }
                status |= CONNECTING;
            }
            context.getExecutor().execute(this);
        }
    }


    // after connection is done, called from a thread pool ( not IO thread )
    // may block for handshake.
    void afterConnect() throws IOException {
        if (hostInfo.secure) {
            blockingStartTLS();
        }

        if ((status & NONBLOCK) != 0) {
            setNonBlocking(); // call again, to set the bits ( connect was blocking )
        }

        setStatus(CONNECTED);
        clearStatus(CONNECTING);
        
        context.onSocket(this);
        notifyIO(false);
    }

    public HostInfo getHost() {
        return hostInfo;
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
                    ByteArrayInputStream bis = new ByteArrayInputStream(
                            certs[i]);
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
        return (context.isServer() ? "AprSrv-" : "AprCli-") + Long.toHexString(socket) + " " + Integer.toHexString(status);
    }

    public int write(byte[] data, int off, int len) throws IOException {
        if (socket == 0 || (status & OUT_CLOSED) != 0) {
            return -1;
        }
        
        int sent = Socket.send(socket, data, off, len);
        if (context.rawDataHandler != null) {
            context.rawData(this, false, data, off, sent, len, false);
        }
        
        if (sent <= 0) {
            if (sent == -Status.TIMEUP) {
                return 0;
            } else if (sent == -Status.EAGAIN) {
                return 0;
            } else if (sent == 0) {
                return 0;
            }
            
            if (context.debug) {
                log.warning("apr.send(): Failed to send, closing socket " + sent);
            }
            error("Error sending " + sent + " " + Error.strerror((int) -sent));
            return sent;
        } else {
            if (sent < len) {
                setStatus(POLLOUT);
            }
            return sent;
        }
    }

    public int read(byte[] data, int off, int len) throws IOException {
        // we can sync, and track 'in progress' - but it's expensive
        // For non-blocking: this is called in IO thread, shouldn't be needed.
        // For blocking: the caller can make sure close/destroy are called after
        // read/write is done.
        if (socket == 0 || (status & IN_CLOSED) != 0) {
            return -1;
        }
        int read = Socket.recv(socket, data, off, len);
        if (context.rawDataHandler != null) {
            context.rawData(this, true, data, off, read, len, false);
        }
        
        if (read > 0) {
            return read;
        }

        if (read == 0 || read == -Status.TIMEUP || read == -Status.ETIMEDOUT 
                || read == -Status.EAGAIN) {
            read = 0;
            setStatus(POLLIN);
            return 0;
        }

        if (read == -Status.APR_EOF) {
            inClosed();
            return -1;
        }
        error("apr.read(): " + read + " " + Error.strerror((int) -read));
        return read;
    }
    
    private void inClosed() {
        synchronized(this) {
            status |= IN_CLOSED;
            status &= ~POLLIN;
            maybeDestroy();
        }
    }
    
    private void outClosed() {
        synchronized(this) {
            status |= OUT_CLOSED;
            status &= ~POLLOUT;
            maybeDestroy();
        }
    }
    
    /**
     * Send FIN, graceful stop. 
     * 
     * Read may continue - use error() if you want to also stop reading.
     * 
     * The actual socket close/destroy will happen only after read() returns -1 and
     * close() has been called. 
     */
    public void writeEnd() throws IOException {
        if ((status & OUT_CLOSED) != 0 || socket == 0) {
            return;
            
        }

        if (context.rawDataHandler != null) {
            context.rawDataHandler.rawData(this, false, null, 0, 0, 0, true);
        }
        // After flush: FIN
        // if data has not been fully flushed: RST
        if (context.debug) {
            log.info("writeEnd: " + context.open.get() + " " + this);
        }
        Socket.shutdown(socket, Socket.APR_SHUTDOWN_WRITE);
        
        outClosed();
    }
    
    void maybeDestroy() {
        synchronized(this) {
            if (socket == 0 ||
                    (status & CONNECTING) != 0) {
                // closed or operation in progress
                return;
            }
            // TODO: can't destroy if still polling.
            if ((status & IN_CLOSED) == 0 ||
                    (status & OUT_CLOSED) == 0) {
                return; // not closed
            }
            if (context.rawDataHandler != null) {
                context.rawDataHandler.rawData(this, false, null, -1, -1, -1, true);
            }
            if (context.debug) {
                log.info("close: " + context.open.get() + " " + this);
            }
            context.open.decrementAndGet();
            Socket.close(socket);
            Socket.destroy(socket);
            socket = 0;
            // if (socketpool != 0) { Pool.destroy(socketpool); }
        }
    }
    
    /**
     * Close input and output, potentially sending RST, than close the socket.
     */
    public void error(String err) {
        log.warning("ERR: " + this + " " + err);
        
        outClosed();
        inClosed();
    }
    
    public void close() throws IOException {
        writeEnd();
        inClosed();
    }


    /**
     * True if read() returned -1
     */
    public boolean isInClosed() {
        synchronized(this) {
            if ((status & IN_CLOSED) != 0 || socket == 0) {
                return true;
            }
            return false;
        }
    }

    /**
     * True if close() has been called.
     */
    public boolean isOutClosed() {
        synchronized(this) {
            if ((status & OUT_CLOSED) != 0 || socket == 0) {
                return true;
            }
            return false;
        }
    }

    private boolean check(int bits, int inProgress) {
        synchronized (this) {
            if ((status & bits) == 0 || socket == 0) {
                return true;
            }
            status |= inProgress;
            return false;
        }
    }

    int requestedPolling() {
        synchronized(this) {
            if (socket == 0) {
                return 0;
            }
            int res = 0;
            if ((status & NONBLOCK) == 0) { // blocking
                if ((res & IN_CLOSED) != 0) {
                    return 0;
                }
                return Poll.APR_POLLNVAL | Poll.APR_POLLHUP | Poll.APR_POLLERR | Poll.APR_POLLIN;
            }
 
            if ((status & POLLIN) != 0) {
                res = Poll.APR_POLLIN;
            }
            if ((status & POLLOUT) != 0) {
                res |= Poll.APR_POLLOUT;
            }
            if (res != 0) {
                res |= Poll.APR_POLLNVAL | Poll.APR_POLLHUP | Poll.APR_POLLERR; 
            }
            return res;
        }
    }
    
    boolean check(int bit) {
        synchronized (this) {
            return ((status & bit) != 0 && socket != 0);
        }
    }

    boolean checkPreConnect(int bit) {
        synchronized (this) {
            return ((status & bit) != 0);
        }
    }

    void clearStatus(int inProgress) {
        synchronized (this) {
            status &= ~inProgress;
            if ((status & (IN_CLOSED |OUT_CLOSED)) == (IN_CLOSED | OUT_CLOSED)) {
                maybeDestroy();
            }            
        }
    }

    boolean setStatus(int inProgress) {
        synchronized (this) {
            int old = status & inProgress;
            status |= inProgress;
            return old != 0;
        }
    }
    
    // Cert is in DER format
    // Called after handshake
    public byte[][] getPeerCert(boolean check) throws IOException {
        getHost();
        if (hostInfo.certs != null && hostInfo.certs != NO_CERTS && !check) {
            return hostInfo.certs;
        }
        if (check(SSL_ATTACHED)) {
            return NO_CERTS;
        }
        try {
            int certLength = SSLSocket.getInfoI(socket,
                    SSL.SSL_INFO_CLIENT_CERT_CHAIN);
            // TODO: if resumed, old certs are good.
            // If not - warn if certs changed, remember first cert, etc.
            if (certLength <= 0) {
                // Can also happen on session resume - keep the old
                if (hostInfo.certs == null) {
                    hostInfo.certs = NO_CERTS;
                }
                return hostInfo.certs;
            }
            hostInfo.certs = new byte[certLength + 1][];

            hostInfo.certs[0] = SSLSocket.getInfoB(socket,
                    SSL.SSL_INFO_CLIENT_CERT);
            for (int i = 0; i < certLength; i++) {
                hostInfo.certs[i + 1] = SSLSocket.getInfoB(socket,
                        SSL.SSL_INFO_CLIENT_CERT_CHAIN + i);
            }
            return hostInfo.certs;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * This is a blocking call ! ( can be made non-blocking, but too complex )
     * 
     * Will be called automatically after connect() or accept if 'secure' is
     * true.
     * 
     * Can be called manually to upgrade the channel
     * @throws IOException 
     */
    public void blockingStartTLS() throws IOException {
        synchronized(this) {
            if (socket == 0) {
                return;
            }
            if ((status & SSL_ATTACHED) != 0) {
                return;
            }
            status |= SSL_ATTACHED;
        }
        
        try {
            if (context.debug) {
                log.info(this + " StartSSL");
            }

            AprSocketContext aprCon = (AprSocketContext) context;
            SSLSocket.attach(aprCon.getSslCtx(), socket);

            if (context.debug) {
                SSLExt.debug(socket);
            }
            if (!((AprSocketContext) getContext()).isServer()) {
                if (context.USE_TICKETS && hostInfo.ticketLen > 0) {
                    SSLExt.setTicket(socket, hostInfo.ticket,
                            hostInfo.ticketLen);
                } else if (hostInfo.sessDer != null) {
                    SSLExt.setSessionData(socket, hostInfo.sessDer,
                            hostInfo.sessDer.length);
                }
            }

        } catch (Exception e) {
            error(e);
            throw new IOException(e);
        }

        try {
            continueHandshake();
        } catch (IOException e) {
            error(e);
            throw new IOException(e);
        }
    }

    /**
     * Can be used for non-blocking tls handshake - too complex.
     * Current use is part of the blocking handshake.
     */
    boolean continueHandshake() throws IOException {
        int rc = SSLSocket.handshake(socket);
        if (context.debug) {
            log.info(this + " ContinueHandshake " + rc);
        }

        if (rc == Status.APR_TIMEUP) {
            if (context.debug) {
                log.info("Timeout in handshake, will continue");
            }
            try {
                log.severe(this + " Handshake failed " + rc + " "
                        + Error.strerror(rc) + " SSLL "
                        + SSL.getLastError());
                error("Handshake failed");
                return false;
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return false;
            }
        } else if (rc != Status.APR_SUCCESS) {
            try {
                log.severe(this + " Handshake failed " + rc + " "
                        + Error.strerror(rc) + " SSLL "
                        + SSL.getLastError());
                error("Handshake failed");
                return false;
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return false;
            }
        } else { // SUCCESS
            if (context.debug) {
                log.info("Handshake OK " + this);
            }
            handshakeDone();
            return true;
        }
    }

    protected void handshakeDone() throws IOException {
        getHost();
        if (socket == 0) {
            throw new IOException("Socket closed");
        }
        if (context.USE_TICKETS && ! context.isServer()) {
            if (hostInfo.ticket == null) {
                hostInfo.ticket = new byte[2048];
            }
            int ticketLen = SSLExt.getTicket(socket, hostInfo.ticket);
            if (ticketLen > 0) {
                hostInfo.ticketLen = ticketLen;
                if (context.debug) {
                    log.info("Received ticket: " + ticketLen);
                }
            }
        }

        // TODO: if the ticket, session id or session changed - callback to 
        // save the session again
        try {
            hostInfo.sessDer = SSLExt.getSessionData(socket);
            getPeerCert(true);
            hostInfo.sessionId = SSLSocket.getInfoS(socket,
                    SSL.SSL_INFO_SESSION_ID);
        } catch (Exception e) {
            throw new IOException(e);
        }

        hostInfo.npn = new byte[32];
        hostInfo.npnLen = SSLExt.getNPN(socket, hostInfo.npn);

        // If custom verification is used - should check the certificates
        if (context.tlsCertVerifier != null) {
            context.tlsCertVerifier.handshakeDone(this);            
        }
    }

    public String getCipherSuite() throws IOException {
        if (check(SSL_ATTACHED)) {
            return null;
        }
        try {
            return SSLSocket.getInfoS(socket, SSL.SSL_INFO_CIPHER);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public int getKeySize() throws IOException {
        if (check(SSL_ATTACHED)) {
            return -1;
        }
        try {
            return SSLSocket.getInfoI(socket, SSL.SSL_INFO_CIPHER_USEKEYSIZE);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public int getRemotePort() throws IOException {
        if (socket != 0) {
            try {
                long sa = Address.get(Socket.APR_REMOTE, socket);
                Sockaddr addr = Address.getInfo(sa);
                return addr.port;
            } catch (Exception ex) {
                throw new IOException(ex);
            }
        }
        throw new IOException("Socket closed");
    }

    public String getRemoteAddress() throws IOException {
        if (socket != 0) {
            try {
                long sa = Address.get(Socket.APR_REMOTE, socket);
                return Address.getip(sa);
            } catch (Exception ex) {
                throw new IOException(ex);
            }
        }
        throw new IOException("Socket closed");
    }

    public String getRemoteHostname() throws IOException {
        if (socket != 0) {
            try {
                long sa = Address.get(Socket.APR_REMOTE, socket);
                String remoteHost = Address.getnameinfo(sa, 0);
                if (remoteHost == null) {
                    remoteHost = Address.getip(sa);
                }
                return remoteHost;
            } catch (Exception ex) {
                throw new IOException(ex);
            }
        }
        throw new IOException("Socket closed");
    }

    public int getLocalPort() throws IOException {
        if (socket != 0) {
            try {
                long sa = Address.get(Socket.APR_LOCAL, socket);
                Sockaddr addr = Address.getInfo(sa);
            } catch (Exception ex) {
                throw new IOException(ex);
            }
        }
        throw new IOException("Socket closed");
    }

    public String getLocalAddress() throws IOException {
        if (socket != 0) {
            try {
                long sa = Address.get(Socket.APR_LOCAL, socket);
                return Address.getip(sa);
            } catch (Exception ex) {
                throw new IOException(ex);
            }
        }
        throw new IOException("Socket closed");
    }

    public String getLocalHostname() throws IOException {
        if (socket != 0) {
            try {
                long sa = Address.get(Socket.APR_LOCAL, socket);
                return Address.getnameinfo(sa, 0);
            } catch (Exception ex) {
                throw new IOException(ex);
            }
        }
        throw new IOException("Socket closed");
    }

    @Override
    public void run() {
        long t0 = System.currentTimeMillis();
        try {
            if (!checkPreConnect(CONNECTED)) {
                if (check(ACCEPTED)) {
                    context.open.incrementAndGet();
                    
                    if (context.debug) {
                        log.info("Accept: " + context.open.get() + " " + this + " " + 
                                getRemotePort());
                    }
                    if (context.tcpNoDelay) {
                        Socket.optSet(socket, Socket.APR_TCP_NODELAY, 1);
                    }

                    setStatus(CONNECTED);
                    if (context.sslMode) {
                        Socket.timeoutSet(socket, context.connectTimeout * 1000);
                        blockingStartTLS();
                    }
                    context.onSocket(this);
                    return;
                } 
                if (checkPreConnect(CONNECTING)) {
                    context.connectBlocking(this);
                }
            } else {
                if (handler != null) {
                    handler.process(this);
                }
            }
        } catch (IOException e) {
            error(e);
        } finally {
            long t1 = System.currentTimeMillis();
            if (t1 - t0 > maxtime.get())  {
                maxtime.set(t1 - t0);
            }
        }
    }
    
    AtomicLong maxtime = new AtomicLong();

    public boolean isBlocking() {
        return !checkPreConnect(NONBLOCK);
    }

}