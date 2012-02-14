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
package org.apache.tomcat.util.net;

import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;


/** 
 * An instance of this class will be associated with the socket and process
 * 'data' events. 
 * 
 * A light processor should not block - the onData() method may be called in the 
 * IO thread, depending on the endpoint ( and conditions ). 
 * 
 * 
 * Light protocol for cases we don't want to preserve a request
 * context  - for example upgraded protocols ( websockets, SPDY ) or 
 * other not-http protocols.
 * 
 * Unlike Handler, ProtocolHandler, this class is associated with and handles a 
 * single socket.
 * 
 */
public interface LightProcessor {
    
    /**
     * Called before destroying the socket.
     */
    public void onClose();
        
    /**
     * Will be called by the endpoint when data can be processed on the associated 
     * socket.
     * 
     * This call should NOT block - and be able to process incomplete data (i.e. socket
     * read returns 0 and doesn't block ).
     * 
     * It should return CLOSE on error or if it wants the socket closed.
     * Returning OPEN means further onData() callbacks will be made.
     * 
     * The associated socket may be blocking - in which case read() will block. The processor
     * should not assume otherwise - blocking read is a a particular case, same as non-blocking
     * when all input is available.
     * 
     * It's up to the endpoint to decide when to give us a blocking socket, what timeout to
     * use on the socket - or to run it in a IO/thread (for fully non-blocking reads) or in a 
     * thread pool.  
     */
    public SocketState onData();
    
    /**
     * Return the associated SocketWrapper
     */
    @SuppressWarnings(value = { "rawtypes"})
    public SocketWrapper getSocket();
}
