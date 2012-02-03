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

import org.apache.tomcat.jni.Status;

/** 
 *
 */
public class LightChannelApr implements LightChannel {
    long socket;
    
    public LightChannelApr(long socket) {
        this.socket = socket;
    }
    
    @Override
    public int write(byte[] data, int off, int len) {
        if (socket == 0) {
            return -1;
        }
        while (len > 0) {
            int sent = org.apache.tomcat.jni.Socket.send(socket, data, off, len);
            if (sent < 0) {
                return -1;
            }
            len -= sent;
            off += sent;
        }
        return len;
    }

    /**
     */
    @Override
    public int read(byte[] data, int off, int len) {
        if (socket == 0) {
            return 0;
        }
        int rd = org.apache.tomcat.jni.Socket.recv(socket, data, off, len);
        if (rd == - Status.APR_EOF) {
            return 0;
        }
        if (rd == -Status.TIMEUP) {
            rd = 0;
        }
        if (rd == -Status.EAGAIN) {
            rd = 0;
        }

        if (rd < 0) {
            return -1;
        }
        off += rd;
        len -= rd;
        return rd;
    }

}