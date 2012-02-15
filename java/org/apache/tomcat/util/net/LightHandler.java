/*
 */
package org.apache.tomcat.util.net;



/** 
 */
public interface LightHandler extends AbstractEndpoint.Handler {

    /**
     * Called in the 'bind' method of the endpoint.
     * 
     * In APR mode will have an extra parameter 'aprSslContext' - this is a one-off
     * for SPDY (or any other protocol needing TLS extensions).
     */
    public void init(AbstractEndpoint ep, long aprSspContext);

    /**
     *  Similar with all the other Handlers. Will be called when the 
     *  socket is accepted or on socket events.
     */
    @SuppressWarnings(value = { "rawtypes"})
    public SocketState process(SocketWrapper socket,  SocketStatus status);

    public void onClose(SocketWrapper<Long> socketWrapper);
}
