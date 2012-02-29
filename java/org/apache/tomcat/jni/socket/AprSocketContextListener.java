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

/**
 * Provide hooks into AprSocketContext.
 * 
 * Methods are typically called from an IO thread - should not block.
 */
public abstract class AprSocketContextListener {

    /** 
     * New channel created - called after accept for server or connect on
     * client. Can be used to save the HostInfo for future use.
     */
    public void channel(AprSocket ch) throws IOException {
        
    }

    /**
     * Delegates loading of persistent info about a host - public certs, 
     * tickets, etc.
     * @param port 
     * @param ssl 
     */
    public HostInfo getPeer(String name, int port, boolean ssl) {
        return null;
    }

    /** 
     * Called when a chunk of data is sent or received. This is very low
     * level, used mostly for debugging or stats. 
     */
    public void rawData(AprSocket ch, boolean input, byte[] data, int pos, 
            int len, boolean closed) {
    }    
    
    /**
     * Called in SSL mode after the handshake is completed.
     * 
     * If @see AprSocketContext.customVerification() was called this 
     * method is responsible to verify the peer certs.
     */
    public void handshakeDone(AprSocket ch) {
        
    }

    /**
     * Called after a channel is fully closed - both input and output are
     * closed, just before the native socket close.
     */
    public void channelClosed(AprSocket ch) {
    }
}