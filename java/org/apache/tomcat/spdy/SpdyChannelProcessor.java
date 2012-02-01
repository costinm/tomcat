/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;


public interface SpdyChannelProcessor {

    void dataFrame(SpdyFrame currentInFrame);

    void setChannelId(int chId);

    void request(SpdyFrame frame) throws IOException;
    
}