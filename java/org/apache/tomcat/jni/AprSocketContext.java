/*
 */
package org.apache.tomcat.jni;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.tomcat.jni.AprSocket.AsyncHandler;

public class AprSocketContext {
    
    /**
     * Information about a remote host.
     * 
     * This class is used in both server and client mode ( with different info ).
     * 
     * IOConnectorHandlers should persist/cache the data, in particular in 
     * SSL mode or in multi-host mode ( clusters ). The goal is to allow 
     * optimizations and extra checks in SSL mode - bypass part of the handshake,
     * remember past certificates - things not possible with JSSE/NIO.
     */
    public class HostInfo implements Serializable {
        
        /**
         * Client: hostname:port of the peer. 
         */
        public String target;
        
        /**
         * Raw cert data (x.509 format).
         * @see IOChannel.getPeerX509Cert() for decoded format.
         */
        public byte[][] certs;

//        byte[] ticket;
//        int ticketLen;
        
        String sessionId;

        /**
         * DER-encoded session data, for client mode session reuse.
         */
        public byte[] sessDer;

        /**
         * Negotiated NPN.
         */
        byte[] npn;
        int npnLen;

        public HostInfo(String target) {
            this.target = target;
        }
        
        public String getNpn() {
            return new String(npn, 0, npnLen); 
        }
    }    

    /**
     * Handle connector-level events.
     * Methods are typically called from an IO thread - should never block. 
     */
    public static abstract class AprSocketListener {

        /** 
         * New channel created - called after accept for server or connect on
         * client.
         * 
         */
        public void channel(AprSocket ch) throws IOException {
            
        }

        /**
         * Delegates loading of persistent info about a host - public certs, 
         * tickets, etc.
         */
        public HostInfo getPeer(String name) {
            return null;
        }
     
        /** 
         * Called when a chunk of data is sent or received. This is very low
         * level, used mostly for debugging or stats. 
         */
        public void rawData(AprSocket ch, boolean inp, byte[] data, int pos, 
                int len, boolean closed) {
        }    
        
        /**
         * Called in SSL mode after the handshake is completed.
         * If @see IOConnector.customVerification() was called this 
         * method is responsible to verify the peer certs.
         */
        public void handshakeDone(AprSocket ch) {
            
        }

        /**
         * Called after a channel is fully closed - both input and output are
         * closed, just before the native socket close.
         *  
         * @param ch
         */
        public void channelClosed(AprSocket ch) {
        }
    }
    
    // If interrupt() or thread-safe poll update are not supported - the 
    // poll updates will happen after the poll() timeout. 
    // The poll timeout with interrupt/thread safe updates can be much higher/ 
    int FALLBACK_POLL_TIME = 2000;
    
    /**
     * For now - single acceptor thread per connector. 
     */
    AcceptorThread acceptor;
    
    /** 
     * Active channels
     */
    List<AprSocket> polledChannels = new ArrayList<AprSocket>();
    
    /** 
     * Poller threads.
     */
    List<AprPoller> pollers = new ArrayList<AprPoller>();
    
    // Set on all accepted or connected sockets.
    boolean tcpNoDelay = true;

    /**
     *  2 sec 
     */
    int connectTimeout = 2000000;
    
    static Logger log = Logger.getLogger("IOConnector");
    
    boolean useFinalizer = true;

    boolean running = true;
    
    static int connectorCounter = 0;
    int connectorId;
    
    int maxSocketsPerPoller = 256;

    protected boolean sslMode;

    
    /**
     * Root APR memory pool.
     */
    static long rootPool = 0;

    /**
     * SSL context.
     */
    protected long sslCtx = 0;
    boolean customTlsVerification = false;

    int MAX_POLL_SIZE = 60;
    
    protected int pollerSize = 8 * 1024;
    int pollerThreadCount;
    int keepAliveTimeout = 20000;
    
    /**
     * Poll interval, in microseconds. If the platform doesn't support 
     * poll interrupt - it'll take this time to stop the poller. 
     * 
     */
    protected int pollTime = 200000000; //200000; // 200 ms
    
//    List<AprPoller> emptyPollers = new ArrayList<AprPoller>();
    
    List<AprSocketListener> connectorHandlers = 
            new ArrayList<AprSocketListener>();
    
    AsyncHandler acceptedHandlers;
    
    // TODO: do we need this here ?
    protected Map<String, HostInfo> hosts = new HashMap();

    String[] enabledCiphers;
    String certFile;
    String keyFile;
    byte[] spdyNPN;
    
    byte[] ticketKey;
    // For resolving DNS ( i.e. connect ), callbacks
    private ExecutorService threadPool;
    public boolean debug = false;

    protected boolean serverMode;

    protected boolean deferAccept = true;

    protected int backlog = 100;

    protected boolean useSendfile;

    public AprSocketContext() {
        super();
        getRootPool();

        if ((OS.IS_WIN32 || OS.IS_WIN64) && (pollerSize > 1024)) {
            // The maximum per poller to get reasonable performance is 1024
            pollerThreadCount = pollerSize / 1024;
            // Adjust poller size so that it won't reach the limit
            pollerSize = pollerSize - (pollerSize % 1024);
        } else {
            // No explicit poller size limitation
            pollerThreadCount = 1;
        }
        connectorId = connectorCounter++;
    }
    
    // "spdy/2"
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
        
    public void addHandler(AprSocketListener handler) {
        connectorHandlers.add(handler);
    }

    public boolean isServerMode() {
        return serverMode;
    }
    
    public void setAcceptedHandler(AsyncHandler h) {
        acceptedHandlers = h;
    }

    public synchronized Executor getExecutor() {
        if (threadPool == null) {
            threadPool = Executors.newCachedThreadPool();
        }
        return threadPool;
    }
    
    public AprSocketContext setSecure(boolean sslMode) {
        this.sslMode = true;
        return this;
    }

    void notifyHandshakeDone(AprSocket ch) throws IOException {
        for (AprSocketListener handler: connectorHandlers) {
            handler.handshakeDone(ch);
        }
        
    }
    
    public void setTicketKey(byte[] key48Bytes) {
        if(key48Bytes.length != 48) {
            throw new RuntimeException("Key must be 48 bytes");
        }
        this.ticketKey = key48Bytes;
    }
    
    public void customVerification() {
        customTlsVerification = true;
    }
    
    public void setEnabledCiphers(String[] enabled) {
        enabledCiphers = enabled;
    }

    public AprSocketContext setKeys(String certPemFile, String keyDerFile)
            throws IOException {
        setSecure(true);
        certFile = certPemFile;
        keyFile = keyDerFile;
        return this;
    }
    
    public HostInfo getPeerInfo(String target) {
        HostInfo pi = hosts.get(target);
        if (pi != null) {
            return pi;
        }
        for (AprSocketListener handler: connectorHandlers) {
            pi = handler.getPeer(target);
            if (pi != null) {
                return pi;
            }
        }        
        if (pi == null) {
            pi = new HostInfo(target);
            hosts.put(target, pi);
        }
        // TODO: max, etc
        return pi;
    }

    void connect(final AprSocket apr, final String host, final int port) {
        getExecutor().execute(new Runnable() {
            public void run() {
                connectBlocking(apr, host, port);
            }
        });
    }
    

    protected void rawData(AprSocket ch, boolean inp, byte[] data, int pos, 
            int len, boolean closed) {
        for (AprSocketListener handler: connectorHandlers) {
            handler.rawData(ch, inp, data, pos, len, closed);
        }
    }

    public void listen(final int port) throws IOException {
        serverMode = true;
        if (acceptor != null) {
            throw new IOException("Already accepting on " + acceptor.port);
        }
        acceptor = new AcceptorThread(port);
        acceptor.prepare();
        acceptor.setName("AprConnectorAcceptor-" + port);
        acceptor.start();
    }
    
    /**
     * Connect happens in a thread pool.
     * We can make it non-blocking by using a non-blocking DNS lookup
     * and apr non-blocking connect.
     * @throws IOException 
     */
    public AprSocket channel() throws IOException {
        return newChannel(this, false);
    }
    
    
    protected void connectBlocking(AprSocket apr, String host, int port) {
        try {
            apr.getPeerInfo();

            //long socketpool = Pool.create(rootPool);

            
            int family = Socket.APR_INET;

            long clientSockP = Socket.create(family,
                    Socket.SOCK_STREAM,
                    Socket.APR_PROTO_TCP, rootPool);
            
            Socket.timeoutSet(clientSockP, connectTimeout); 
            if (OS.IS_UNIX) {
                Socket.optSet(clientSockP, Socket.APR_SO_REUSEADDR, 1);
            }

            // TODO: option
            Socket.optSet(clientSockP, Socket.APR_SO_KEEPALIVE, 1);

            // Blocking 
            // TODO: use socket pool
            long inetAddress = Address.info(host, Socket.APR_INET,
                  port, 0, rootPool);
            int rc = Socket.connect(clientSockP, inetAddress);
        
            if (rc != 0) {
                Socket.close(clientSockP);
                apr.error("Socket.connect(): " + Error.strerror(rc));
                /////Pool.destroy(socketpool);
                return;
            }
            
            if (tcpNoDelay) {
                Socket.optSet(clientSockP, Socket.APR_TCP_NODELAY, 1);
            }
            
            //Socket.timeoutSet(clientSockP, 0);
            apr.socket = clientSockP;
            //apr.socketpool = socketpool;

            for (AprSocketListener handler: connectorHandlers) {
                handler.channel(apr);
            }
            
            apr.handleConnected();
        } catch (Exception e) {
            e.printStackTrace();
            
        }
    }

    static AprSocket newChannel(AprSocketContext connector, 
            boolean acccepted) throws IOException {
        AprSocket res = connector.useFinalizer ? new FinalizedAprChannel() 
            : new AprSocket();
        res.factory = connector;
        res.connected = acccepted;
        return res;
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
        if (threadPool != null) {
            threadPool.shutdownNow();
        }
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
                try {
                    a.join();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            // Should distroy all other native resources creted by this connector
            Pool.destroy(rootPool);
            rootPool = 0;
        }
    }

    private static long getRootPool() {
        if (rootPool == 0) {
            try {
                Library.initialize(null);
                SSL.initialize(null);                
            } catch (Exception e) {
                throw new RuntimeException("APR not present", e);
            }
            // Create the root APR memory pool
            rootPool = Pool.create(0);
        }
        return rootPool;
    }
    
    int sslProtocol = SSL.SSL_PROTOCOL_TLSV1;
    
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
    
    long getSslCtx() throws Exception {
        if (sslCtx == 0) {
            sslCtx = SSLContext.make(rootPool, 
                    sslProtocol,
                    serverMode ? SSL.SSL_MODE_SERVER : SSL.SSL_MODE_CLIENT);

            // SSL.SSL_OP_NO_SSLv3 
            int opts = SSL.SSL_OP_NO_SSLv2 |
                SSL.SSL_OP_SINGLE_DH_USE;
            
            if (serverMode && ticketKey == null) {
                opts |= SSL.SSL_OP_NO_TICKET;
            }
            
            //SSLContext.setOptions(sslCtx, opts);
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
                    if (customTlsVerification) {
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
    
    
    protected void updatePolling(AprSocket ch) {
        if (ch.poller != null) {
            ch.poller.updatePolling(ch, false);
            return;
        }
        
        AprPoller target = null;
        synchronized (pollers) {
            // needs a new poller
            if (ch.socket == 0) {
                log.warning(connectorId + " No socket " + ch);
                return;
            }
            if (debug) {
                log.info(connectorId + " Waiting for poll " + ch);
            }
            int min = Integer.MAX_VALUE;
            for (AprPoller poller: pollers) {
                int cnt = poller.keepAliveCount.get();
                if (cnt > maxSocketsPerPoller) {
                    continue;
                }
                if (min > cnt) {
                    target = poller;
                    min = cnt;
                }
                // if any is empty, wake up
                if (cnt < 1) {
                    target = poller;
                    break;
                }
            }
            // TODO: find a poller, more than 1 poller
            if (target == null) {// or not enough
                target = new AprPoller();
                target.setName("AprPoller " + ch.socket);
                pollers.add(target);
                target.start();
            }
        }
        
        target.updatePolling(ch, true);
    }

    static class FinalizedAprChannel extends AprSocket {
        private Throwable t;
        
        public FinalizedAprChannel() {
            super();
            this.t = new Throwable();
        }
        
        protected void finalize() {
            if (socket != 0) {
                log.log(Level.SEVERE, this + " Socket not closed", t);
            }
        }
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
                serverSockPool = Pool.create(rootPool);

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
                long socketpool = Pool.create(rootPool);
                long inetAddress = Address.info("127.0.0.1", Socket.APR_INET,
                        port, 0, socketpool);
                int family = Socket.APR_INET;
                long clientSockP = Socket.create(family,
                        Socket.SOCK_STREAM,
                        Socket.APR_PROTO_TCP, socketpool);
                int rc = Socket.connect(clientSockP, inetAddress);
                if (rc != 0) {
                    if (debug) {
                        // ignore
                    }
                } else {
                    Socket.close(clientSockP);                    
                }
                Pool.destroy(socketpool);
            } catch (Exception ex) {
                // ignore - the acceptor may have shut down by itself.
            }
        }
        
        @Override
        public void run() {
            while (running) {
                try {
                    // each socket has a pool.
                    long socket = Socket.accept(serverSock);
                    
                    Socket.optSet(socket, Socket.APR_SO_NONBLOCK, 1);
                    if (tcpNoDelay) {
                        Socket.optSet(socket, Socket.APR_TCP_NODELAY, 1);
                    }
                    Socket.timeoutSet(socket, 0);

                    final AprSocket ch =  
                            AprSocketContext.newChannel(AprSocketContext.this, true);
                    
                    ch.socket = socket;
                    
                    if (sslMode) {
                        getExecutor().execute(new Runnable() { 
                            public void run() {
                                try {
                                    ch.blockingStartTLS();
                                    onAccepted(ch);
                                } catch (Throwable t) {
                                    ch.error(t);
                                }
                            }
                        });
                    } else {
                        try {
                            onAccepted(ch);
                        } catch (Throwable t) {
                            ch.error(t);
                        }
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            cleanup();
        }
        
        void onAccepted(AprSocket ch) throws IOException {
            for (AprSocketListener handler: connectorHandlers) {
                handler.channel(ch);
            }
            if (acceptedHandlers != null) {
                ch.addIOHandler(acceptedHandlers);
            }
            // We may already have data in the input
            ch.notifyIO(0, false);
        }
    }
    
  
    class AprPoller extends Thread {

        protected long serverPollset = 0;
        protected long pool = 0;
        protected long[] desc;
        
        Map<Long, AprSocket> channels = new HashMap<Long, AprSocket>();
        
        /**
         * Apr supportes thread safe updates
         */
        private boolean threadSafe = true;
        
        /**
         * APR supports interrupt
         */
        private boolean interrupt = true;
        
        protected AtomicInteger keepAliveCount = new AtomicInteger();
        
        private List<AprSocket> updates = new ArrayList<AprSocket>();
        private List<AprSocket> updating = new ArrayList<AprSocket>();
        
        private ReentrantLock pollerLock = new ReentrantLock();
        private Condition noChannelsCond = pollerLock.newCondition();
        
        private Thread myThread;
        

        long updatesChanged;
        public AprPoller() {
            init();
            setDaemon(true);
        }
        
        /**
         * Allocate a new poller of the specified size.
         */
        protected long allocatePoller(int size, long pool, int timeout) {
            int flag = (threadSafe) ? Poll.APR_POLLSET_THREADSAFE : 0;
            for (int i = 0; i < 2; i++) {
                try {
                    //  timeout must be -1 - or ttl will take effect, strange results.
                    return Poll.create(size, pool, flag, -1); // timeout * 1000);
                } catch (Error e) {
                    if (Status.APR_STATUS_IS_EINVAL(e.getError())) {
                        log.info(connectorId + " endpoint.poll.limitedpollsize " + size);
                        return 0;
                    } else if (Status.APR_STATUS_IS_ENOTIMPL(e.getError())) {
                        // thread safe not supported
                        log.severe("THREAD SAFE NOT SUPPORTED" + e);
                        threadSafe = false;
                        // try again without the flags
                        continue;
                    } else {
                        log.severe("endpoint.poll.initfail" + e);
                        return -1;
                    }
                }
            }
            log.severe("Unexpected ENOTIMPL with flag==0");
            return -1;
        }
        
        /**
         * Create the poller. With some versions of APR, the maximum poller size will
         * be 62 (recompiling APR is necessary to remove this limitation).
         */
        protected void init() {
            pool = Pool.create(rootPool);
            int size = pollerSize / pollerThreadCount;
            int timeout = keepAliveTimeout;
            
            serverPollset = allocatePoller(size, pool, timeout);
            if (serverPollset == 0 && size > 1024) {
                size = 1024;
                serverPollset = allocatePoller(size, pool, timeout);
            }
            if (serverPollset == 0) {
                size = 62;
                serverPollset = allocatePoller(size, pool, timeout);
            }
            
            desc = new long[size * 2];
        }

        /**
         * Destroy the poller.
         */
        protected void destroyPoller() {
            pollers.remove(this);
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
                    try {
                        channels.get(desc[n*2+1]).close();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
            Pool.destroy(pool);
        }
        
        int to = 10000;

        
        /** 
         * Called only in poller thread.
         */
        private void updates() {
            pollerLock.lock();
            try {
                List<AprSocket> tmp = updates;
                updates = updating;
                updating = tmp;
                updatesChanged = 0;
            } finally {
                pollerLock.unlock();
            }
            for (AprSocket up: updating) {
                if (up.socket == 0) {
                    continue;
                }
                if (debug)
                    log.info("Delayed update " + 
                            (System.currentTimeMillis() - updatesChanged) +
                            " " + up);
                pollUpdate(up, up.socket, true);
            }
            updating.clear();
        }
        
        /** 
         * Called from any thread.
         */
        void updatePolling(AprSocket ioch, boolean added) {
            AprSocket ch = (AprSocket) ioch;
            if (added) {
                pollerLock.lock();
                try {
                    channels.put(ch.socket, ch); 
                    if (debug) {
                        log.info("starting polling " + ch  + (threadSafe ? " now" : " delayed"));
                    }
                    ch.poller = this;
                } finally {
                    pollerLock.unlock();
                }
            }
            if (threadSafe || Thread.currentThread() == myThread) {
                if (ch.socket == 0) {
                    return;
                }
                pollUpdate(ch, ch.socket, false);
            } else {
                pollerLock.lock();
                try {
                    updates.add(ch);
                    noChannelsCond.signal();
                    if (updatesChanged == 0) {
                        updatesChanged = System.currentTimeMillis();
                    }
                    interruptPoll();
                } finally {
                    pollerLock.unlock();
                }
            }
        }

        private void interruptPoll() {
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
        
        /** 
         * Actual poll update - called in the polling thread or 
         * if thread safe in any thread.
         */
        private void pollUpdate(AprSocket up, long sock, boolean ioThread) {
            int rv = Status.APR_SUCCESS;
            String poll = "-";
            if (! up.isOpen()) { // FIN received
                if (up.isOutClosed()) {
                    if (ioThread) {
                        pollerLock.lock();
                        try {
                            up.pollOut = false;
                            channels.remove(up.socket); 
                            up.poller = null;

                            if (up.socket != 0) {
                                if (up.pollIn) {
                                    rv = Poll.remove(serverPollset, up.socket); 
                                    if (rv != Status.APR_SUCCESS) {
                                        System.err.println("Failed to remove " +Error.strerror((int)rv) + 
                                                " " + Long.toHexString(up.socket));
                                        rv = Status.APR_SUCCESS;
                                    }
                                }
                                up.pollIn = false;

                                try {
                                    up.notifyIO(0, true);
                                } catch (IOException ex) {
                                    ex.printStackTrace();
                                }
                                for (AprSocketListener handler: connectorHandlers) {
                                    handler.channelClosed(up);
                                }
                                
                                Socket.close(up.socket);
                                // Can only be destroyed after we make sure it's not 
                                // polled
                                Socket.destroy(up.socket);
                                up.socket = 0;
                                
                                

//                              if (socketpool != 0) {
//                              Pool.destroy(socketpool);
//                          }
                                
                            }

                        } finally {
                            pollerLock.unlock();
                        }
                        if (debug) {
                            log.info("poll close " + up + " ");
                        }
                    } else {
                        pollerLock.lock();
                        try {
                            updates.add(up);
                            noChannelsCond.signal();
                            if (updatesChanged == 0) {
                                updatesChanged = System.currentTimeMillis();
                            }
                            interruptPoll();
                        } finally {
                            pollerLock.unlock();
                        }
                    }

                    
                    
                } else {
                    if (up.pollOut) {
                        // still needs output polling
                        // TODO: will need to increment keepAliveCount ?
                        System.err.println("TODO: pollUpdate() Flush in closed");
                    }
                }
            } else {
                pollerLock.lock();
                try {
                    if (up.socket == 0) {
                        return;
                    }
                    if (up.pollIn) {
                        rv = Poll.remove(serverPollset, up.socket); 
                        if (rv != Status.APR_SUCCESS) {
                            System.err.println("Failed to remove " +Error.strerror((int)rv) + 
                                    " " + Long.toHexString(up.socket));
                            rv = Status.APR_SUCCESS;
                        }
                    } else {
                        keepAliveCount.incrementAndGet();                        
                    }
                    rv = Poll.add(serverPollset, up.socket, 
                            (up.pollOut) ? 
                                    Poll.APR_POLLIN | Poll.APR_POLLOUT : 
                                        Poll.APR_POLLNVAL | Poll.APR_POLLHUP | Poll.APR_POLLERR | Poll.APR_POLLIN);
                    up.pollIn = true;
                    poll = up.pollOut ? "IO" : "I";
                    
                    if (debug && keepAliveCount.get() < 2) {
                        log.info("POLL: signal " + keepAliveCount);
                    }
                    noChannelsCond.signal();
                } finally {
                    pollerLock.unlock();
                }
                
            }

            
            if (debug) {
                log.info(connectorId + " pollUpdate " + poll +
                        " res=" + rv + " " + up );
            }
            
            if (rv != Status.APR_SUCCESS) {
                log.info("poll remove - error adding " +  rv + " " + up);                        
                // Can't do anything: close the socket right away
                up.error("ERR: Poll.add " + rv + " " + Error.strerror((int)rv));
            }

//            if (up.getIn().isAppendClosed() &&
//                    up.getOut().isClosedAndEmpty()) {
//                // doesn't expect more in, out is done
//                Poll.remove(serverPollset, sock);
//                try {
//                    up.realClose();
//                } catch (IOException e) {
//                }
//            }
        }
        
        public void run() {
            myThread = Thread.currentThread();
            if (debug) {
                log.info(connectorId + " Starting poll");
            }
            while (running) {
                try {
                    long t0 = System.currentTimeMillis();
                    pollerLock.lock();
                    try {
                        updates();
                        if (debug) {
                            int cnt = Poll.pollset(serverPollset, desc);
                            if (cnt != keepAliveCount.get()) {
                                log.info("POLL: Wrong keepalive " + cnt + " " + keepAliveCount);
                            }
                        }
                        if (keepAliveCount.get() <= 0) {
                            noChannelsCond.await(to, TimeUnit.MILLISECONDS);
                            if (keepAliveCount.get() <= 0) {
                                continue; // process updates
                            } else {
                                if (debug) {
                                    log.info("POLL: no waiting channels");
                                }
                                break;
                            }
                        }
                    } catch (InterruptedException ex) {
                        continue;
                    } finally {
                        pollerLock.unlock();
                    }
                    
                    // Pool for the specified interval
                    // Don't remove explicitely
                    int rv = Poll.poll(serverPollset, pollTime, desc, true);
                    long t1 = System.currentTimeMillis();
                    if (debug) {
                        if (rv == -Status.TIMEUP) {
                            if (t1 - t0 < pollTime / 2000 ) {
                                log.info(connectorId + " Poll: TIMEUP " + pollTime + " real:" + (t1 - t0));
                            }
                        } else {
                            log.info(connectorId + " Poll " + rv + " waiting " + keepAliveCount
                                 + " t=" + (t1 - t0) + " updates:" + updates.size());
                        }
                    }
                    if (rv > 0) {
                        pollerLock.lock();
                        try {
                            keepAliveCount.addAndGet(-rv);
                            for (int n = 0; n < rv; n++) {
                                long sock = desc[n*2+1];
                                synchronized(channels) {
                                    AprSocket ch = channels.get(sock);
                                    if (ch != null) {
                                        ch.pollIn = false;
                                    }
                                }
                            }                            
                        } finally {
                            pollerLock.unlock();
                        }
                        for (int n = 0; n < rv; n++) {
                            long sock = desc[n*2+1];
                            AprSocket ch;
                            synchronized(channels) {
                                ch = channels.get(sock);
                            }
                            // We just removed it ( see last param to poll()).
                            // Check for failed sockets and hand this socket off to a worker
                            long mask = desc[n*2];
                            
                            boolean hup = ((mask & Poll.APR_POLLHUP) == Poll.APR_POLLHUP);
                            boolean err = ((desc[n*2] & Poll.APR_POLLERR) == Poll.APR_POLLERR);
                            boolean out = (mask & Poll.APR_POLLOUT) == Poll.APR_POLLOUT;
                            boolean in = (mask & Poll.APR_POLLIN) == Poll.APR_POLLIN;

                            if (ch == null) {
                                log.info("Polled socket without channel " + Long.toHexString(sock) +
                                        (hup ? " HUP " : "") +
                                        (err ? " ERR " : "") +
                                        (out ? " OUT " : "") +
                                        (in ? " IN " : "") +
                                        " " );
                                continue;
                            }
                            
                            if (debug) {
                                log.info(connectorId + " Polled " + mask + " " +
                                        (hup ? " HUP " : "") +
                                        (err ? " ERR " : "") +
                                        (out ? " OUT " : "") +
                                        (in ? " IN " : "") +
                                        ch + " " + sock);
                            }
                            if (err) {
                                ch.error("Poller error");
                                continue;
                            }
                            if (out || in || hup) {
                                // try to send if needed
                                ch.notifyIO(0, hup);                                
                            }
                            
                            pollUpdate(ch, desc[n * 2 + 1], true);
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
                                destroyPoller();
                                init();
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
    }
}
