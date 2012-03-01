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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.tomcat.jni.Address;
import org.apache.tomcat.jni.Error;
import org.apache.tomcat.jni.Library;
import org.apache.tomcat.jni.OS;
import org.apache.tomcat.jni.Poll;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.SSL;
import org.apache.tomcat.jni.SSLContext;
import org.apache.tomcat.jni.SSLExt;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

public class AprSocketContext {
    /** 
     * Called when a chunk of data is sent or received. This is very low
     * level, used mostly for debugging or stats. 
     */
    public static interface RawDataHandler {
        public void rawData(AprSocket ch, boolean input, byte[] data, int pos, 
                int len, int requested, boolean closed);
    }

    /**
     * Called in SSL mode after the handshake is completed.
     * 
     * @see AprSocketContext.customVerification()
     */
    public static interface TlsCertVerifier {
        public void handshakeDone(AprSocket ch);
    }
    
    /**
     * Delegates loading of persistent info about a host - public certs, 
     * tickets, config, persistent info etc.
     */
    public static interface HostInfoLoader {
        public HostInfo getHostInfo(String name, int port, boolean ssl); 
    }
    
    /** 
     * Reads/writes of this size or lower are using Get/SetByteArrayRegion.
     * Larger reads use Get/ReelaseByteArrayElements.
     * Larger writes use malloc/free + GetByteArrayRagion.
     */
    static final int TCN_BUFFER_SZ = 8192;

    static Logger log = Logger.getLogger("AprSocket");
    
    // If interrupt() or thread-safe poll update are not supported - the 
    // poll updates will happen after the poll() timeout. 
    // The poll timeout with interrupt/thread safe updates can be much higher/ 
    static int FALLBACK_POLL_TIME = 2000;
    static int MAX_POLL_SIZE = 60;
    
    // It seems to send the ticket, get server helo / ChangeCipherSpec, but than
    // SSL3_GET_RECORD:decryption failed or bad record mac in s3_pkt.c:480:
    // Either bug in openssl, or some combination of ciphers - needs more debugging.
    // ( this can save a roundtrip and CPU on TLS handshake )
    boolean USE_TICKETS = false;
        
    boolean useFinalizer = true;

    /**
     * For now - single acceptor thread per connector. 
     */
    AcceptorThread acceptor;
    
    // APR/JNI is thread safe
    boolean threadSafe = true;
    
    /** 
     * Pollers. 
     */
    List<AprPoller> pollers = new ArrayList<AprPoller>();
    static int pollerCnt = 0;
    
    // Set on all accepted or connected sockets.
    // TODO: add the other properties
    boolean tcpNoDelay = true;
    
    protected boolean running = true;
    
    protected boolean sslMode;
    
    /**
     * Root APR memory pool.
     */
    private long rootPool = 0;

    /**
     * SSL context.
     */
    private long sslCtx = 0;

    TlsCertVerifier tlsCertVerifier;

    private int pollerSize = 8 * 1024;
    
    int connectTimeout =  20000;
    int defaultTimeout = 100000;
    
    int keepAliveTimeout = 20000;
    
    AtomicInteger open = new AtomicInteger();
    
    /**
     * Poll interval, in microseconds. If the platform doesn't support 
     * poll interrupt - it'll take this time to stop the poller. 
     * 
     */
    protected int pollTime = 10000000; //200000; // 200 ms
    
    HostInfoLoader hostInfoLoader;

    RawDataHandler rawDataHandler = null;
    
    // TODO: do we need this here ?
    protected Map<String, HostInfo> hosts = new HashMap<String, HostInfo>();

    String[] enabledCiphers;
    
    String certFile;
    String keyFile;
    
    byte[] spdyNPN;
    
    byte[] ticketKey;
    
    // For resolving DNS ( i.e. connect ), callbacks
    private ExecutorService threadPool;

    // Separate executor for pollers - will set thread names.
    private ExecutorService pollerExecutor;
    
    boolean debug = false;
    boolean debugPoll = false;

    protected boolean deferAccept = false;

    protected int backlog = 100;

    protected boolean useSendfile;

    int sslProtocol = SSL.SSL_PROTOCOL_TLSV1;

    public AprSocketContext() {
        pollerExecutor = Executors.newCachedThreadPool();
    }
    
    /**
     * Poller thread count.
     */
    protected int pollerThreadCount = 4;
    public void setPollerThreadCount(int pollerThreadCount) { this.pollerThreadCount = pollerThreadCount; }
    public int getPollerThreadCount() { return pollerThreadCount; }
    
    public void setBacklog(int backlog) { if (backlog > 0) this.backlog = backlog; }
    public int getBacklog() { return backlog; }
    
    /**
     * Defer accept.
     */
    public void setDeferAccept(boolean deferAccept) { this.deferAccept = deferAccept; }
    public boolean getDeferAccept() { return deferAccept; }
    
    /**
     * For client: 
     *   - ClientHello will include the npn extension ( the ID == 0x3374) 
     *   - if ServerHello includes a list of protocols - select one
     *   - send it after ChangeCipherSpec and before Finish
     *   
     *  For server:
     *   - if ClientHello includes the npn extension 
     *    -- will send this string as list of supported protocols in ServerHello
     *   - read the selection before Finish.
     * @param npn
     */
    public void setNpn(String npn) {
        spdyNPN = new byte[npn.length() + 2];
        System.arraycopy(npn.getBytes(), 0, spdyNPN, 1, npn.length());
        spdyNPN[0] = (byte) npn.length();
        spdyNPN[npn.length() + 1] = 0;        
    }
        
    public void setHostLoader(HostInfoLoader handler) {
        this.hostInfoLoader = handler;
    }

    public boolean isServer() {
        return acceptor != null;
    }
    
    protected Executor getExecutor() {
        if (threadPool == null) {
            threadPool = Executors.newCachedThreadPool();
        }
        return threadPool;
    }
    
    /**
     * All accepted sockets will start handshake automatically.
     */
    public AprSocketContext setSecureServer() {
        this.sslMode = true;
        return this;
    }

    public void setTcpNoDelay(boolean b) {
        tcpNoDelay = b;
    }
    
    public void setSslProtocol(String protocol) {
        protocol = protocol.trim();
        if ("SSLv2".equalsIgnoreCase(protocol)) {
            sslProtocol = SSL.SSL_PROTOCOL_SSLV2;
        } else if ("SSLv3".equalsIgnoreCase(protocol)) {
            sslProtocol = SSL.SSL_PROTOCOL_SSLV3;
        } else if ("TLSv1".equalsIgnoreCase(protocol)) {
            sslProtocol = SSL.SSL_PROTOCOL_TLSV1;
        } else if ("all".equalsIgnoreCase(protocol)) {
            sslProtocol = SSL.SSL_PROTOCOL_ALL;
        }        
    }
    
    public void setTicketKey(byte[] key48Bytes) {
        if(key48Bytes.length != 48) {
            throw new RuntimeException("Key must be 48 bytes");
        }
        this.ticketKey = key48Bytes;
    }
    
    public void customVerification(TlsCertVerifier verifier) {
        tlsCertVerifier = verifier;
    }
    
    public void setEnabledCiphers(String[] enabled) {
        enabledCiphers = enabled;
    }

    public AprSocketContext setKeys(String certPemFile, String keyDerFile)
            throws IOException {
        this.sslMode = true;
        setSecureServer();
        certFile = certPemFile;
        keyFile = keyDerFile;
        return this;
    }
    
    /**
     * Override or use hostInfoLoader to implement persistent/memcache storage.
     */
    public HostInfo getHostInfo(String host, int port, boolean ssl) {
        if (hostInfoLoader != null) {
            return hostInfoLoader.getHostInfo(host, port, ssl);
        }
        // Use local cache
        String key = host + ":" + port;
        HostInfo pi = hosts.get(key);
        if (pi != null) {
            return pi;
        }
        pi = new HostInfo(host, port, ssl);
        hosts.put(key, pi);
        return pi;
    }

    protected void rawData(AprSocket ch, boolean inp, byte[] data, int pos, 
            int len, int requested, boolean closed) {
        if (rawDataHandler != null) {
            rawDataHandler.rawData(ch, inp, data, pos, len, requested, closed);
        }
    }

    public void listen(final int port) throws IOException {
        if (acceptor != null) {
            throw new IOException("Already accepting on " + acceptor.port);
        }
        if (sslMode && certFile == null) {
            throw new IOException("Missing certificates for server");
        }
        acceptor = new AcceptorThread(port);
        acceptor.prepare();
        acceptor.setName("AprAcceptor-" + port);
        acceptor.start();
    }
    
    /**
     * Get a socket for connectiong to host:port.
     */
    public AprSocket socket(String host, int port, boolean ssl) throws IOException {
        HostInfo hi = getHostInfo(host, port, ssl);
        return socket(hi);
    }
    
    public AprSocket socket(HostInfo hi) throws IOException {
        AprSocket sock = newSocket(this);
        sock.setHost(hi);
        return sock;
    }    
    
    protected void connectBlocking(AprSocket apr) {
        try {
            HostInfo hi = apr.getHost();

            long socketpool = Pool.create(getRootPool());

            
            int family = Socket.APR_INET;

            long clientSockP = Socket.create(family,
                    Socket.SOCK_STREAM,
                    Socket.APR_PROTO_TCP, socketpool); // or rootPool ?
            
            Socket.timeoutSet(clientSockP, connectTimeout * 1000); 
            if (OS.IS_UNIX) {
                Socket.optSet(clientSockP, Socket.APR_SO_REUSEADDR, 1);
            }

            // TODO: option
            Socket.optSet(clientSockP, Socket.APR_SO_KEEPALIVE, 1);

            // Blocking 
            // TODO: use socket pool
            // TODO: cache it ( and TTL ) in hi
            long inetAddress = Address.info(hi.host, Socket.APR_INET,
                  hi.port, 0, rootPool);
            int rc = Socket.connect(clientSockP, inetAddress);
        
            if (rc != 0) {
                Socket.close(clientSockP);
                Socket.destroy(clientSockP);
                apr.error("Socket.connect(): " + Error.strerror(rc) + " " + connectTimeout);
                /////Pool.destroy(socketpool);
                return;
            }
            
            connectionsCount.incrementAndGet();
            if (tcpNoDelay) {
                Socket.optSet(clientSockP, Socket.APR_TCP_NODELAY, 1);
            }

            Socket.timeoutSet(clientSockP, defaultTimeout * 1000); 
            
            apr.socket = clientSockP;
            
            apr.afterConnect();
        } catch (Exception e) {
            e.printStackTrace();
            
        }
    }

    AprSocket newSocket(AprSocketContext context) throws IOException {
        return context.useFinalizer ? new FinalizedAprSocket(context) 
            : new AprSocket(context);
    }

    /**
     * To clean the pools - we could track if all channels are
     * closed, but this seems simpler and safer.
     */
    protected void finalize() {
        if (rootPool != 0) {
            log.warning(this + " GC without stop()");
        }
        try {
            stop();
        } catch (Exception e) {
            //TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    

    public void stop() throws IOException {
        running = false;
        
        if (rootPool != 0) {
            if (acceptor != null) {
                try {
                    acceptor.unblock();
                    acceptor.join();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }  
            for (AprPoller a: pollers) {
                a.interruptPoll();
            }
            // Should distroy all other native resources creted by this connector
            Pool.destroy(rootPool);
            rootPool = 0;
        }
        if (threadPool != null) {
            threadPool.shutdownNow();
        }
        pollerExecutor.shutdownNow();
        
    }
    
    private long getRootPool() throws IOException {
        if (rootPool == 0) {
            try {
                Library.initialize(null);
                SSL.initialize(null);                
            } catch (Exception e) {
                throw new IOException("APR not present", e);
            }
            // Create the root APR memory pool
            rootPool = Pool.create(0);

            // Adjust poller sizes
            if ((OS.IS_WIN32 || OS.IS_WIN64) && (pollerSize > 1024)) {
                // The maximum per poller to get reasonable performance is 1024
                pollerThreadCount = pollerSize / 1024;
                // Adjust poller size so that it won't reach the limit
                pollerSize = pollerSize - (pollerSize % 1024);
            }
        }
        return rootPool;
    }
    
    long getSslCtx() throws Exception {
        if (sslCtx == 0) {
            boolean serverMode = acceptor != null;
            sslCtx = SSLContext.make(getRootPool(), 
                    sslProtocol,
                    serverMode ? SSL.SSL_MODE_SERVER : SSL.SSL_MODE_CLIENT);

            // SSL.SSL_OP_NO_SSLv3 
            int opts = SSL.SSL_OP_NO_SSLv2 |
                SSL.SSL_OP_SINGLE_DH_USE;
            
            if (!USE_TICKETS || serverMode && ticketKey == null) {
                opts |= SSL.SSL_OP_NO_TICKET;
            }
            
            SSLContext.setOptions(sslCtx, opts);
            // Set revocation
            //        SSLContext.setCARevocation(sslContext, SSLCARevocationFile, SSLCARevocationPath);
            
            // Client certificate verification - maybe make it option
            try {
                SSLContext.setCipherSuite(sslCtx, "ALL");
                
                
                if (serverMode) {
                    if (ticketKey != null) {
                        //SSLExt.setTicketKeys(sslCtx, ticketKey, ticketKey.length);
                    }
                    if (certFile != null) {
                        boolean rc = SSLContext.setCertificate(sslCtx, 
                                certFile,
                                keyFile, null, SSL.SSL_AIDX_DSA);
                        if (!rc) {
                            throw new IOException("Can't set keys");
                        }
                    }
                    SSLContext.setVerify(sslCtx, SSL.SSL_CVERIFY_NONE, 10);
                    
                    if (spdyNPN != null) {
                        SSLExt.setNPN(sslCtx, spdyNPN, spdyNPN.length);
                    }
                } else {
                    if (tlsCertVerifier != null) {
                        // NONE ? 
                        SSLContext.setVerify(sslCtx, 
                                SSL.SSL_CVERIFY_NONE, 10);                        
                    } else {
                        SSLContext.setCACertificate(sslCtx, 
                                "/etc/ssl/certs/ca-certificates.crt", 
                                "/etc/ssl/certs");
                        SSLContext.setVerify(sslCtx, 
                                SSL.SSL_CVERIFY_REQUIRE, 10);
                    }
                    
                    if (spdyNPN != null) {
                        SSLExt.setNPN(sslCtx, spdyNPN, spdyNPN.length);
                    }
                }
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException(e);
            }
            
        }
        return sslCtx;
    }
    
    
    /**
     * Request read polling for a blocking socket.
     * 
     * Resume polling for a non-blocking socket.
     */
    void poll(AprSocket ch) throws IOException {
        if (ch.poller != null) {
            if (ch.isBlocking()) {
                throw new IOException("Poll already called");
            } else {
                return; // redundant call for non-blocking
            }
        }
        if (ch.isInClosed()) {
            throw new IOException("Closed");            
        }
        // When adding - we need POLLIN, it's automatic after read/write
        if (!ch.isBlocking()) {
            ch.setStatus(AprSocket.POLLIN);
        }
        synchronized (pollers) {
            // Make sure we have min number of pollers
            int needPollers = pollerThreadCount - pollers.size();
            if (needPollers > 0) {
                for (int i = needPollers; i > 0; i--) {
                    pollers.add(allocatePoller());
                }
            }
            int max = 0;
            AprPoller target = null;
            for (AprPoller poller: pollers) {
                int rem = poller.remaining();
                if (rem > max) {
                    target = poller;
                    max = rem;
                }
            }
            if (target != null && target.add(ch)) {
                return;
            } 
            // can't be added - add a new poller 
            AprPoller poller = allocatePoller();
            poller.add(ch);
            pollers.add(poller);
        }
    }

    static class FinalizedAprSocket extends AprSocket {
        public FinalizedAprSocket(AprSocketContext context) {
            super(context);
        }
        
        protected void finalize() {
            if (socket != 0) {
                log.log(Level.SEVERE, this + " Socket not closed");
                error("Socket not closed");
            }
        }
    }

    /**
     * Called on each accepted socket ( for servers ) or after connection (client)
     * after handshake.
     */
    protected void onSocket(AprSocket s) throws IOException {
        
    }

    class AcceptorThread extends Thread {
        int port;
        long serverSockPool = 0;
        long serverSock = 0;

        final String addressStr = null;

        long inetAddress;
        
        AcceptorThread(int port) {
            this.port = port;
            setDaemon(true);
        }
        
        void prepare() throws IOException {
            try {
                // Create the pool for the server socket
                serverSockPool = Pool.create(getRootPool());

                int family = Socket.APR_INET;
                inetAddress = Address.info(addressStr, family,
                        port, 0, serverSockPool);

                // Create the APR server socket
                serverSock = Socket.create(family,
                        Socket.SOCK_STREAM,
                        Socket.APR_PROTO_TCP, serverSockPool);

                if (OS.IS_UNIX) {
                    Socket.optSet(serverSock, Socket.APR_SO_REUSEADDR, 1);
                }
                // Deal with the firewalls that tend to drop the inactive sockets
                Socket.optSet(serverSock, Socket.APR_SO_KEEPALIVE, 1);
                // Bind the server socket
                int ret = Socket.bind(serverSock, inetAddress);
                if (ret != 0) {
                    throw new IOException("Socket.bind " + ret + " " + 
                            Error.strerror(ret) + " port=" + port);
                }
                // Start listening on the server socket
                ret = Socket.listen(serverSock, backlog );
                if (ret != 0) {
                    throw new IOException("endpoint.init.listen" 
                            + ret + " " + Error.strerror(ret));
                }
                if (OS.IS_WIN32 || OS.IS_WIN64) {
                    // On Windows set the reuseaddr flag after the bind/listen
                    Socket.optSet(serverSock, Socket.APR_SO_REUSEADDR, 1);
                }

                // Sendfile usage on systems which don't support it cause major problems
                if (useSendfile && !Library.APR_HAS_SENDFILE) {
                    useSendfile = false;
                }

                // Delay accepting of new connections until data is available
                // Only Linux kernels 2.4 + have that implemented
                // on other platforms this call is noop and will return APR_ENOTIMPL.
                if (deferAccept) {
                    if (Socket.optSet(serverSock, Socket.APR_TCP_DEFER_ACCEPT, 1) == Status.APR_ENOTIMPL) {
                        deferAccept = false;
                    }
                }
            } catch (Throwable t) {
                throw new IOException(t);
            }
        }
        
        void cleanup() {
            Socket.close(serverSock);
        }
        
        void unblock() {
            try {
                // Easiest ( maybe safest ) way to interrupt accept
                // we could have it in non-blocking mode, etc
                AprSocket cli = socket("127.0.0.1", port, false);
                cli.connect();
                cli.error("Abort");
            } catch (Exception ex) {
                // ignore - the acceptor may have shut down by itself.
            }
        }
        
        @Override
        public void run() {
            while (running) {
                try {
                    // each socket has a pool.
                    final AprSocket ch = newSocket(AprSocketContext.this);
                    ch.setStatus(AprSocket.ACCEPTED);
                    ch.socket = Socket.accept(serverSock);
                    connectionsCount.incrementAndGet();
                    getExecutor().execute(ch);
                } catch (Throwable e) {
                    e.printStackTrace();
                }
            }
            cleanup();
        }
    }

    AtomicInteger connectionsCount = new AtomicInteger();
    
    /**
     * Create the poller. With some versions of APR, the maximum poller size will
     * be 62 (recompiling APR is necessary to remove this limitation).
     * @throws IOException 
     */
    AprPoller allocatePoller() throws IOException {
        long pool = Pool.create(getRootPool());
        int size = pollerSize / pollerThreadCount;
        int timeout = keepAliveTimeout;
        
        long serverPollset = allocatePoller(size, pool, timeout);

        if (serverPollset == 0 && size > 1024) {
            size = 1024;
            serverPollset = allocatePoller(size, pool, timeout);
        }
        if (serverPollset == 0) {
            size = 62;
            serverPollset = allocatePoller(size, pool, timeout);
        }
        
        AprPoller res = threadSafe ? new AprPoller() : new AprPollerNotThreadSafe();
        res.pool = pool;
        res.serverPollset = serverPollset;
        res.desc = new long[size * 2];
        return res;
    }
    
    protected long allocatePoller(int size, long pool, int timeout) {
        int flag = threadSafe ? Poll.APR_POLLSET_THREADSAFE: 0;
        for (int i = 0; i < 2; i++) {
            try {
                //  timeout must be -1 - or ttl will take effect, strange results.
                return Poll.create(size, pool, flag, -1); // timeout * 1000);
            } catch (Error e) {
                e.printStackTrace();
                if (Status.APR_STATUS_IS_EINVAL(e.getError())) {
                    log.info(" endpoint.poll.limitedpollsize " + size);
                    return 0;
                } else if (Status.APR_STATUS_IS_ENOTIMPL(e.getError())) {
                    // thread safe not supported
                    log.severe("THREAD SAFE NOT SUPPORTED" + e);
                    threadSafe = false;
                    // try again without the flags
                    continue;
                } else {
                    log.severe("endpoint.poll.initfail" + e);
                    return 0;
                }
            }
        }
        log.severe("Unexpected ENOTIMPL with flag==0");
        return 0;
    }
    
  
    class AprPoller implements Runnable {

        protected long serverPollset = 0;
        protected long pool = 0;
        protected long[] desc;
        private boolean interrupt = true;
        
        
        Map<Long, AprSocket> channels = new HashMap<Long, AprSocket>();
        
        protected AtomicInteger keepAliveCount = new AtomicInteger();
        
        protected Thread myThread;
        
        /**
         * Destroy the poller.
         */
        protected void destroyPoller() {
            synchronized (pollers) {
                pollers.remove(this);
            }
            // Wait for polltime before doing anything, so that the poller threads
            // exit, otherwise parallel destruction of sockets which are still
            // in the poller can cause problems
            try {
                synchronized (this) {
                    this.wait(pollTime / 1000);
                }
            } catch (InterruptedException e) {
                // Ignore
            }
            // Close all sockets still in the poller
            int rv = Poll.pollset(serverPollset, desc);
            if (rv > 0) {
                for (int n = 0; n < rv; n++) {
                    channels.get(desc[n*2+1]).error("Poll.destroy()");
                }
            }
            Pool.destroy(pool);
        }
        
        int to = 10000;

        /** 
         * Called from any thread.
         * @throws IOException 
         */
        boolean add(AprSocket ch) throws IOException {
            synchronized (channels) {
                if (!addChannel(ch)) {
                    return false;
                }
                realAddOrUpdate(ch);
                if (channels.size() == 1) {
                    getExecutor().execute(this);
                }
                return true;
            }
        }

        int remaining() {
            synchronized (channels) {
                return (desc.length - channels.size() * 2);
            }            
        }
        
        protected boolean addChannel(AprSocket ch) throws IOException {
            synchronized (channels) {
                if (ch.poller != null) {
                    throw new IOException("Already polling " + ch);
                }
    
                if (channels.size() * 2 > desc.length) {
                    return false;
                }
                channels.put(ch.socket, ch);
                return true;
            }
        }

        /** 
         * Actual poll update - called in the polling thread or 
         * if thread safe in any thread.
         * @throws IOException 
         */
        protected void realAddOrUpdate(AprSocket up) throws IOException {
            int rv = Status.APR_SUCCESS;
            
            int req = up.requestedPolling();

            boolean polling = up.poller != null;
            if (polling && up.isBlocking()) {
                throw new IOException("Update for blocking socket " + up);
            }
            
            synchronized (channels) {
                if (polling) { // non blocking - update
                    // It is already polling - maybe for something else.
                    synchronized (AprSocketContext.class) {
                        rv = Poll.remove(serverPollset, up.socket);
                    }
                    if (rv != Status.APR_SUCCESS) {
                        log.severe("Failed to remove " +Error.strerror((int)rv) + 
                                " " + up);
                        rv = Status.APR_SUCCESS;
                    } else {
                        keepAliveCount.decrementAndGet();
                    }
                    if (req == 0) {
                        // No longer polling for this socket
                        up.poller = null;
                        channels.remove(up.socket); 

                        // In case it was delayed because polling had to be removed
                        up.maybeDestroy();
                        if (debug) {
                            log.info("pollUpdate - remove " + req + " res=" + rv + " " + up );
                        }
                        return;
                    }
                    // else: will add it back
                }

                synchronized (AprSocketContext.class) {
                    rv = Poll.add(serverPollset, up.socket, req);                    
                }
                if (debugPoll) {
                    log.info("pollUpdate " + Integer.toHexString(req) + " res=" + rv + " " + up );
                }
            }
            if (rv != Status.APR_SUCCESS) {
                log.info("poll remove - error adding " +  rv + " " + up);                        
                // Can't do anything: close the socket right away
                up.error("ERR: Poll.add " + rv + " " + Error.strerror((int)rv));
            } else {
                keepAliveCount.incrementAndGet();
                up.poller = this;
            }
        }
        
        /** 
         * Called from any thread.
         */
        boolean updateNonBlocking(AprSocket ch) throws IOException {
            synchronized (channels) {
                realAddOrUpdate(ch);
            }
            return true;
        }

        /**
         * For non-blocking, to simplify the poll update only happens 
         * after the handler has been called. 
         */
        private void pollUpdateNB(AprSocket up, long sock) {
            synchronized(channels) {
                int req = up.requestedPolling();
                if (req == 0) {
                    // no longer interested in polling
                    channels.remove(sock);
                    up.poller = null;
                    // In case it was delayed because polling had to be removed
                    up.maybeDestroy();
                    if (debug) {
                        log.info("pollUpdate - remove nb " + up );
                    }
                    return;
                }

                int rv = Status.APR_SUCCESS;
                synchronized (AprSocketContext.class) {
                    rv = Poll.add(serverPollset, up.socket, req);
                }
                if (debugPoll) {
                    log.info("pollUpdate " + Integer.toHexString(req) + " res=" + rv + " " + up );
                }
                if (rv != Status.APR_SUCCESS) {
                    log.info("poll update NB - error adding " +  rv + " " + up);                        
                    // Can't do anything: close the socket right away
                    channels.remove(sock);
                    up.poller = null;
                    up.error("ERR: Poll.add " + rv + " " + Error.strerror((int)rv));
                } else {
                    keepAliveCount.incrementAndGet();
                }
            }
        }
        
        public void run() {
            myThread = Thread.currentThread();
            log.info("Starting poller " + (isServer() ? "SRV ": "CLI ") + (desc.length / 2));
            if (debug) {
                myThread.setName("Poller " + pollerCnt++);
            }
            while (running) {
                try {
                    long t0 = System.currentTimeMillis();
                    synchronized (channels) {
                        updates();
                        if (channels.size() == 0) {
                            break;
                        }
                    }
                    
                    // Pool for the specified interval. Remove signaled sockets
                    int rv = Poll.poll(serverPollset, pollTime, desc, true);
                    if (!running) {
                        break;
                    }
                    long t1 = System.currentTimeMillis();
                    if (debugPoll) {
                        debugAfterPoll(t0, rv, t1);
                    }
                    if (rv > 0) {
                        keepAliveCount.addAndGet(-rv);
                        for (int pollIdx = 0; pollIdx < rv; pollIdx++) {
                            long sock = desc[pollIdx * 2 + 1];
                            AprSocket ch;
                            synchronized (channels) {
                                ch = channels.get(sock);
                                if (ch != null) {
                                    if (ch.isBlocking()) {
                                        channels.remove(sock);
                                        ch.poller = null;
                                    }
                                } else {
                                    log.severe("Polled socket not found !!!!!" + Long.toHexString(sock));
                                    continue;
                                }
                            }

                            // We just removed it ( see last param to poll()).
                            // Check for failed sockets and hand this socket off to a worker
                            long mask = desc[pollIdx * 2];
                            if (debugPoll) {
                                log.info(" Polled " + Long.toHexString(mask) + " " + ch);
                            }

                            boolean hup = ((mask & Poll.APR_POLLHUP) == Poll.APR_POLLHUP);
                            boolean err = ((mask & Poll.APR_POLLERR) == Poll.APR_POLLERR);
                            boolean out = (mask & Poll.APR_POLLOUT) == Poll.APR_POLLOUT;
                            boolean in = (mask & Poll.APR_POLLIN) == Poll.APR_POLLIN;

//                            if (err) {
//                                ch.setStatus(AprSocket.ERROR);
//                                ch.notifyIO(true);                                
//                                ch.error("POLERR");
//                                continue;
//                            }
//                            if (hup) {
//                                ch.setStatus(AprSocket.ERROR);
//                                ch.notifyIO(true);                                
//                                ch.error("Poller hup");
//                                continue;
//                            }
                            if (out || in || hup || err) {
                                // try to send if needed
                                ch.notifyIO(true);                                
                            }
                            if (!ch.isBlocking()) {
                                // Blocking: notifyIO is in a thread, most likely 
                                // won't need polling until timeouts.
                                pollUpdateNB(ch, sock);
                            }
                        }
                    } else if (rv < 0) {
                        int errn = -rv;
                        if (errn == Status.TIMEUP) {
                            // ignore
                        } else if (errn == Status.EINTR) {
                            log.info("Poll: EINTR");                            
                        } else {
                            /* Any non timeup or interrupted error is critical */
                            if (errn >  Status.APR_OS_START_USERERR) {
                                errn -=  Status.APR_OS_START_USERERR;
                            }
                            log.severe("endpoint.poll.fail " + errn + " " + Error.strerror(errn));
                            // Handle poll critical failure
                            synchronized (this) {
                                destroyPoller(); // will close all sockets
                            }
                            continue;
                        } 
                    }
                    // TODO: timeouts
                } catch (Throwable t) {
                    log.log(Level.SEVERE, "endpoint.poll.error", t);
                }

            }

            if (debug) {
                log.info("Poll done");
            }

            synchronized (this) {
                this.notifyAll();
            }
        }

        protected void updates() throws IOException {
        }

        private void debugAfterPoll(long t0, int rv, long t1) {
            if (rv == -Status.TIMEUP) {
                if (t1 - t0 < pollTime / 2000 ) {
                    log.info(" Poll: TIMEUP " + pollTime + " real:" + (t1 - t0));
                }
            } else {
                log.info(" Poll " + rv + " waiting " + keepAliveCount
                     + " t=" + (t1 - t0) );
            }
        }
        
        void interruptPoll() {
            if (interrupt) {
                try {
                    int rc = Poll.interrupt(serverPollset);
                    if (rc != Status.APR_SUCCESS) {
                        log.severe("Failed interrupt and not thread safe");
                    }
                } catch (Throwable t) {
                    interrupt = false;
                    if (pollTime > FALLBACK_POLL_TIME) {
                        pollTime = FALLBACK_POLL_TIME;
                    }
                }
            }
        }
        
    }
    
    // TODO: not tested / not used in recent past, most tests done with thread-safe apr.
    class AprPollerNotThreadSafe extends AprPoller {
        private List<AprSocket> updates = new ArrayList<AprSocket>();
        private List<AprSocket> updating = new ArrayList<AprSocket>();
        long updatesChanged;
     

        /** 
         * Called only in poller thread, only used if not thread safe
         * @throws IOException 
         */
        protected void updates() throws IOException {
            synchronized (channels) {
                List<AprSocket> tmp = updates;
                updates = updating;
                updating = tmp;
                updatesChanged = 0;
                for (AprSocket up: updating) {
                    if (up.isInClosed() && up.isOutClosed()) {
                        continue;
                    }
                    if (debug)
                        log.info("Delayed update " + 
                                (System.currentTimeMillis() - updatesChanged) +
                                " " + up);
                    realAddOrUpdate(up);
                }
                updating.clear();
            }
        }
        
        /** 
         * Called from any thread.
         */
        boolean add(AprSocket ch) throws IOException {
            synchronized (channels) {
                if (!addChannel(ch)) {
                    return false;
                }
                if (channels.size() == 1) {
                    // Just added - this is the first, need to start thread.
                    realAddOrUpdate(ch);
                    pollerExecutor.execute(this);
                    return true;
                }
                updates.add(ch);
                if (updatesChanged == 0) {
                    updatesChanged = System.currentTimeMillis();
                }
                interruptPoll();
            }
            return true;
        }
        
        /** 
         * Called from any thread.
         */
        boolean updateNonBlocking(AprSocket ch) throws IOException {
            synchronized (channels) {
                updates.add(ch);
                if (updatesChanged == 0) {
                    updatesChanged = System.currentTimeMillis();
                }
                interruptPoll();
            }
            return true;
        }
    }
    
}
