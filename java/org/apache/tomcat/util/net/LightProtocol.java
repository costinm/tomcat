/*
 */
package org.apache.tomcat.util.net;



/** 
 * Alternative protocol that can be switched dynamically on the socket 
 * connection. Tomcat will start with the default http protocol ( with one of the 
 * 3 endpoints ), the light protocol can be selected based on socket properties
 * or configuration.
 * 
 * Can be set up as "lightProtocol" attribute in the <Connector> element.
 */
public interface LightProtocol {

	/**
	 * Called in the 'bind' method of the endpoint.
	 * 
	 * In APR mode will have an extra parameter 'aprSslContext' - this is a one-off
	 * for SPDY (or any other protocol needing TLS extensions).
	 */
    public void init(AbstractEndpoint ep, long aprSspContext);

    /**
     * Called when a socket has been accepted. 
     * 
     * @return null if normal HTTP should continue - it may use socket info
     * like SSL next protocol.
     * 
     * TODO: add read/write methods to SocketWrapper.
     * There is no point in adding another abstraction - Nio already subclasses
     * it, and it's easy to do for APR and JIO with minimal side-effects. This will
     * also remove the need for long/Long boxing.
     */
    @SuppressWarnings(value = { "rawtypes"})
    public LightProcessor getProcessor(SocketWrapper socket);
    
    // TODO: stop() ? 
}
