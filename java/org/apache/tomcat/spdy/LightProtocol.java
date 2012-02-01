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
package org.apache.tomcat.spdy;


/** 
 * Light protocol for cases we don't want to preserve a request
 * context  - for example upgraded protocols ( websockets, SPDY ) or 
 * other not-http protocols.
 *
 * The current implementation is blocking, but it is possible to add hooks 
 * into NIO and APR endpoints. 
 * 
 * Unlike Handler, ProtocolHandler, this class is associated with and handles a 
 * single socket.
 */
public interface LightProtocol {
    public static final int OPEN = 1;
    public static final int CLOSE = -1;
    
    /**
     * Called before destroying the socket.
     */
    public void onClose();
        
    /**
     * Called when data is received. This is NOT called in the poll thread,
     * but in a thread pool. 
     * 
     * The protocol can either block, or consume all input until read() returns
     * 0 and return OPEN, in which case the caller will have to poll. 
     * 
     * JIO will never retun 0 on read(), so the code will be all blocking.
     */
    public int onData();
    
    public void setSocket(LightChannel socket);
}
