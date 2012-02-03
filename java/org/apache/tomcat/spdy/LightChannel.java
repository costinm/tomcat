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

import java.io.IOException;

/**
 * Minimal interface for blocking read/write. 
 * 
 * The actual channel may or may not be backed by a socket.
 * 
 * There is no close() - the blocking protocol should return when done, 
 * the endpoint will close.
 * 
 * TODO: add 'wouldBlock' or other indication that read will block, in some 
 * cases we may return the socket to the poll.
 * 
 * MEMORY: please keep it light, just minimal state.
 */
public interface LightChannel {
    
    /** 
     * Write. The current implementation is blocking - write is typically
     * invoked from user code running in the thread pool, so it should be 
     * ok to block.
     *  
     * TODO: add a separate non-blocking write, with a callback 
     * and flow control to support output in the IO thread. 
     */
    public int write(byte[] data, int off, int len) throws IOException;
    
    /**
     * Like read, but may return 0 if no data is available and the channel
     * supports polling. 
     */
    public int read(byte[] data, int off, int len) throws IOException;
}