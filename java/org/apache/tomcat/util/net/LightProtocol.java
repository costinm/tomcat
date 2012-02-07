/*
 */
package org.apache.tomcat.util.net;

import java.net.Socket;


/** 
 * Alternative protocol that can be switched dynamically on the socket 
 * connection.
 */
public interface LightProtocol {

    
    public LightProcessor getProcessor(long socket);
    
    // One-off, for APR contexts
    public void init(long aprContext, AbstractEndpoint ep);

    public LightProcessor getProcessor(Socket socket);
}
