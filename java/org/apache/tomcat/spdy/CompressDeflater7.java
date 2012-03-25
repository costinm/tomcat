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
import java.util.zip.Deflater;

/**
 * Java7 Deflater.
 * 
 * TODO: Class.forName/detection to plug it in.
 */
class CompressDeflater7 extends CompressDeflater6 {

    public CompressDeflater7() {
    }

    @Override
    public synchronized void compress(SpdyFrame frame, int start)
            throws IOException {
        init();

        if (compressBuffer == null) {
            compressBuffer = new byte[frame.data.length];
        }

        // last byte for flush ?
        zipOut.setInput(frame.data, start, frame.endData - start);
        int coff = start;
        int dfl = zipOut.deflate(compressBuffer, coff, compressBuffer.length - coff,
                Deflater.SYNC_FLUSH);
        coff += dfl;

        byte[] tmp = frame.data;
        frame.data = compressBuffer;
        compressBuffer = tmp;
        frame.endData = coff;
    }

}
