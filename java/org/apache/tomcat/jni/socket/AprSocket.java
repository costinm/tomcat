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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
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

    static AtomicInteger handshakeTimeouts = new AtomicInteger();

    static AtomicInteger handshakeErrors = new AtomicInteger();

    static AtomicInteger handshakeOk = new AtomicInteger();

    static AtomicInteger channelCnt = new AtomicInteger();


    public static int CONNECTING = 1;
    public static int CONNECTED = 0x2;
    
    public static int READING = 0x4; // 0x04 
    public static int WRITING = 0x8; // 0x08
    
    public static int IN_CLOSED = 0x10;
    public static int OUT_CLOSED = 0x20;
    public static int SSL_ATTACHED = 0x40;

    public static int POLLIN = 0x80;
    public static int POLLOUT = 0x100;

    public static int ACCEPTED = 0x200;
    public static int ERROR = 0x400;

    AprSocketContext context;

    // only one - to save per/socket memory - context has similar callbacks.
    AprSocketHandler handler;

    AprPoller poller;
    
    private Lock channelLock = new ReentrantLock();

    // Bit field indicating the status and socket should only be accessed with 
    // socketLock protection
    private int status;
    
    long socket;

    // used for blocking. TODO: use in non-blocking as well
    long ioTimeout = 10000; // ms

    // Last activity timestamp.
    public long ts;

    // Persistent info about the peer ( SSL, etc )
    HostInfo hostInfo;

    protected String errorMessage;

    private boolean blocking = true;

    public void recycle() {
        status = 0;
        hostInfo = null;
        ts = 0;
        handler = null;
        errorMessage = null;
        ioTimeout = 10000;
        socket = 0;
        poller = null;
    }

    public AprSocket() {
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

    void notifyIO(boolean needThread) throws IOException {
        ts = System.currentTimeMillis();
        try {
            if (handler != null) {
                if (!needThread) {
                    handler.process(this);
                    return;
                }
                if (blocking) {
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
        }
    }

    public void setHandler(AprSocketHandler l) {
        handler = l;
    }
    
    /**
     * For blocking: read poll.
     * 
     * @throws IOException
     */
    public void poll() throws IOException {
        context.poll(this);
    }

    // TODO: update
    public void suspendRead() throws IOException {
        if (blocking) {
            throw new IOException("suspendRead() on blocking " + this);
        }
        clearStatus(POLLIN);
    }

    public AprSocketContext getContext() {
        return context;
    }

    public void setBlocking(boolean block) {
        this.blocking = block;
        if (socket != 0) {
            if (block) {
                Socket.optSet(socket, Socket.APR_SO_NONBLOCK, 0);
                Socket.timeoutSet(socket, ioTimeout);
            } else {
                Socket.optSet(socket, Socket.APR_SO_NONBLOCK, 1);
                Socket.timeoutSet(socket, 0);
            }
        }
    }

    public AprSocket setTarget(HostInfo hi) {
        hostInfo = hi;
        return this;
    }
     
    /**
     * Non-blocking connect method
     */
    public void connect() throws IOException {
        if (blocking) {
            context.connectBlocking(this, hostInfo);
            // will call handleConnected() at the end.
        } else {
            channelLock.lock();
            try {
                if ((status & CONNECTING) == 0) {
                    return;
                }
                status |= CONNECTING;
            } finally {
                channelLock.unlock();
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

        Socket.timeoutSet(socket, ioTimeout * 1000);

        if (! blocking) {
            setBlocking(false);
        }

        setStatus(CONNECTED);
        clearStatus(CONNECTING);
        notifyIO(false);
    }

    public HostInfo getPeerInfo() {
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
        return "AprCh-" + Long.toHexString(socket) + " " + Integer.toHexString(status);
    }

    public int write(byte[] data, int off, int len) throws IOException {
        channelLock.lock();
        try {
            if (socket == 0 || (status & OUT_CLOSED) != 0) {
                return -1;
            }
            status |= WRITING;
        } finally {
            channelLock.unlock();
        }
        
        int sent = Socket.send(socket, data, off, len);
        ts = System.currentTimeMillis();
        clearStatus(WRITING);

        if (sent == -Status.TIMEUP) {
            if (context.debugRW) {
                log.info("apr.send TIMEUP");
            }
            sent = 0;
        } else if (sent == -Status.EAGAIN) {
            sent = 0;
        }

        if (sent < 0) {
            if (context.debug) {
                log.warning("apr.send(): Failed to send, closing socket " + sent);
            }
            error("Error sending " + sent + " " + Error.strerror((int) -sent));
            return sent;
        } else {
            if (sent > 0) {
                context.rawData(this, false, data, off, sent, false);
            }
            if (sent < len) {
                if (context.debugRW) {
                    log.warning("apr.send(): Incomplete send, poll out");
                }
                setStatus(POLLOUT);
            }
            if (context.debugRW) {
                log.info("apr.send() " + sent);
            }
            return sent;
        }
    }

    public int read(byte[] data, int off, int len) throws IOException {
        channelLock.lock();
        try {
            if (socket == 0 || (status & IN_CLOSED) != 0) {
                return -1;
            }
            status |= READING;
        } finally {
            channelLock.unlock();
        }
        int read = Socket.recv(socket, data, off, len);
        ts = System.currentTimeMillis();
        clearStatus(READING);

        if (read == -Status.TIMEUP || read == -Status.ETIMEDOUT) {
            read = 0;
        }
        if (read == -Status.EAGAIN) {
            read = 0;
        }
        if (read == -Status.APR_EOF) {
            log.info("apr.read(): EOF " + this);
            inClosed();
            context.rawData(this, true, null, 0, read, true);
            return -1;
        }
        if (read < 0) {
            String msg = socket + " apr.read(): " + read + " "
                    + Error.strerror((int) -read);
            log.info(msg);
            error(msg);
            return read;
        }
        if (context.debugRW)
            log.info(socket + " apr.read(): " + read);
        if (read > 0) {
            context.rawData(this, true, null, 0, read, false);
        } else {
            setStatus(POLLIN);
        }

        return read;
    }
    
    private void inClosed() {
        channelLock.lock();
        try {
            status |= IN_CLOSED;
            status &= ~POLLIN;
            maybeDestroy();
        } finally {
            channelLock.unlock();
        }
    }
    
    private void outClosed() {
        channelLock.lock();
        try {
            status |= OUT_CLOSED;
            status &= ~POLLOUT;
            maybeDestroy();
        } finally {
            channelLock.unlock();
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
        channelLock.lock();
        try {
            if ((status & OUT_CLOSED) != 0 || socket == 0) {
                return;
            }
            status |= WRITING;
        } finally {
            channelLock.unlock();
        }

        if (context.debug) {
            log.info("FIN: " + this);
        }
        // After flush: FIN
        // if data has not been fully flushed: RST
        Socket.shutdown(socket, Socket.APR_SHUTDOWN_WRITE);
        
        clearStatus(WRITING);
        outClosed();
    }
    
    void maybeDestroy() {
        channelLock.lock();
        try {
            if (socket == 0 ||
                    (status & (WRITING | READING | CONNECTING)) != 0) {
                // closed or operation in progress
                return;
            }
            // TODO: can't destroy if still polling.
            if ((status & IN_CLOSED) == 0 ||
                    (status & OUT_CLOSED) == 0) {
                return; // not closed
            }
            if (context.debug) {
                log.info("Destroy " + context.open.decrementAndGet() + " " + this);
            }
            Socket.close(socket);
            Socket.destroy(socket);
            socket = 0;
            // if (socketpool != 0) { Pool.destroy(socketpool); }
        } finally {
            channelLock.unlock();
        }
    }
    
    /**
     * Close input and output, potentially sending RST, than close the socket.
     */
    public void error(String err) {
        errorMessage = err;
        log.warning("ERR: " + socket + " " + err);
        
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
        channelLock.lock();
        try {
            if ((status & IN_CLOSED) != 0 || socket == 0) {
                return true;
            }
            return false;
        } finally {
            channelLock.unlock();
        }
    }

    /**
     * True if close() has been called.
     */
    public boolean isOutClosed() {
        channelLock.lock();
        try {
            if ((status & OUT_CLOSED) != 0 || socket == 0) {
                return true;
            }
            return false;
        } finally {
            channelLock.unlock();
        }
    }

    private boolean check(int bits, int inProgress) {
        channelLock.lock();
        try {
            if ((status & bits) == 0 || socket == 0) {
                return true;
            }
            status |= inProgress;
            return false;
        } finally {
            channelLock.unlock();
        }
    }

    int requestedPolling() {
        channelLock.lock();
        try {
            if (socket == 0) {
                return 0;
            }
            int res = 0;
            if (blocking) {
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
        } finally {
            channelLock.unlock();
        }
    }
    
    boolean check(int bit) {
        channelLock.lock();
        try {
            return ((status & bit) != 0 && socket != 0);
        } finally {
            channelLock.unlock();
        }
    }

    void clearStatus(int inProgress) {
        channelLock.lock();
        try {
            status &= ~inProgress;
            if ((status & (IN_CLOSED |OUT_CLOSED)) == (IN_CLOSED | OUT_CLOSED)) {
                maybeDestroy();
            }
        } finally {
            channelLock.unlock();
        }
    }

    boolean setStatus(int inProgress) {
        channelLock.lock();
        try {
            int old = status & inProgress;
            status |= inProgress;
            return old != 0;
        } finally {
            channelLock.unlock();
        }
    }
    
    /** 
     * If error() is called both in and out will be closed non-gracefully.
     * 
     * @return Error code, or null if error() has not been called. 
     */
    public String errorMessage() {
        return errorMessage;
    }

    // Cert is in DER format
    // Called after handshake
    public byte[][] getPeerCert(boolean check) throws IOException {
        getPeerInfo();
        if (hostInfo.certs != null && hostInfo.certs != NO_CERTS && !check) {
            return hostInfo.certs;
        }
        if (check(SSL_ATTACHED, READING)) {
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
        } finally {
            clearStatus(READING);
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
        channelLock.lock();
        try {
            if (socket == 0) {
                return;
            }
            if ((status & SSL_ATTACHED) != 0) {
                return;
            }
            status |= SSL_ATTACHED;
        } finally {
            channelLock.unlock();
        }
        
        try {
            if (context.debug) {
                log.info(this + " StartSSL");
            }

            AprSocketContext aprCon = (AprSocketContext) context;
            SSLSocket.attach(aprCon.getSslCtx(), socket);

            if (context.debugRW) {
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
        if (context.debugRW) {
            log.info(this + " ContinueHandshake " + rc);
        }

        if (rc == Status.APR_TIMEUP) {
            if (context.debug) {
                log.info("Timeout in handshake, will continue");
            }
            // will continue.
            handshakeTimeouts.incrementAndGet();
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
            handshakeErrors.incrementAndGet();
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
            if (context.debugRW) {
                log.info("Handshake OK " + this);
            }
            handshakeOk.incrementAndGet();
            handshakeDone();
            return true;
        }
    }

    protected void handshakeDone() throws IOException {
        getPeerInfo();
        if (socket == 0) {
            throw new IOException("Socket closed");
        }
        if (context.USE_TICKETS && ! context.serverMode) {
//            if (hostInfo.ticket == null) {
//                hostInfo.ticket = new byte[2048];
//            }
//            int ticketLen = SSLExt.getTicket(socket, hostInfo.ticket);
//            if (ticketLen > 0) {
//                hostInfo.ticketLen = ticketLen;
//                if (context.debug) {
//                    log.info("Received ticket: " + ticketLen);
//                }
//            }
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
        context.notifyHandshakeDone(this);
    }

    public String getCipherSuite() throws IOException {
        if (check(SSL_ATTACHED, READING)) {
            return null;
        }
        try {
            return SSLSocket.getInfoS(socket, SSL.SSL_INFO_CIPHER);
        } catch (Exception e) {
            throw new IOException(e);
        } finally {
            clearStatus(READING);
        }
    }

    public int getKeySize() throws IOException {
        if (check(SSL_ATTACHED, READING)) {
            return -1;
        }
        try {
            return SSLSocket.getInfoI(socket, SSL.SSL_INFO_CIPHER_USEKEYSIZE);
        } catch (Exception e) {
            throw new IOException(e);
        } finally {
            clearStatus(READING);
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
        if (socket != 0) {// && remoteAddress == null) {
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
        try {
            if (!check(CONNECTED)) {
                if (check(ACCEPTED)) {
                    setStatus(CONNECTED);
                    if (context.sslMode) {
                        Socket.timeoutSet(socket, context.connectTimeout);
                        blockingStartTLS();
                    }
                    context.onAccepted(this);
                    return;
                } 
                if (check(CONNECTING)) {
                    context.connectBlocking(this, hostInfo);
                    
                }
            } else {
                if (handler != null) {
                    handler.process(this);
                }
            }
        } catch (IOException e) {
            error(e);
        }
    }

    public boolean isBlocking() {
        return blocking;
    }

}