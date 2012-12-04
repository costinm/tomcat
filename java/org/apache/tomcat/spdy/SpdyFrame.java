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

import java.util.Map;

// TODO: to support multiple versions ( or other framed protocols ) we could
// turn this into a base class.

/**
 * Frames are exposed as a low-level interface - Input/OutputStreams are 
 * implemented on top of frames, but it can be more efficient to use the 
 * frames.
 */
public class SpdyFrame {

    public static byte[] METHOD = ":method".getBytes();

    public static byte[] PATH = ":path".getBytes();

    public static byte[] HOST = ":host".getBytes();

    public static byte[] SCHEME = ":scheme".getBytes();

    public static byte[] STATUS = ":status".getBytes();

    public static byte[] VERSION = ":version".getBytes();

    public static byte[] HTTP11 = "HTTP/1.1".getBytes();

    public static byte[] OK200 = "200 OK".getBytes();

    public static byte[] HTTP = "http".getBytes();

    public static byte[] HTTPS = "https".getBytes();


    private static byte[] URL = {'u', 'r', 'l'};

    // This is a bit more complicated, to avoid multiple reads/writes.
    // We'll read as much as possible - possible past frame end. This may
    // cost an extra copy if multiple frames are read in one IO.
    
    // Format: 
    //  - first 8 bytes are header
    //  - content is between 'off' and 'endData'
    //  - parts of next frame between 'endData' and 'endReadData'
    // After read the header is parsed and the 'extra' is moved to the next frame.
    public byte[] data;

    public int off = 8; // used when reading - current offset

    int endReadData; // how much has been read ( may be more or less than a frame )

    // On write it is incremented.

    /**
     *  end of data in the buffer == frame body length + 8 (header)
     */
    public int endData;

    // Processed data from the frame
    boolean c; // for control

    int version;

    int flags;

    public int type;

    // For control frames
    public int streamId;

    public int pri;

    public int associated;

    public int nvCount;

    public SpdyStream stream;

    public SpdyFrame(int size) {
        data = new byte[size];
    }

    public int getDataSize() {
        return endData - 8;
    }

    public void recyle() {
        type = 0;
        c = false;
        endReadData = 0;
        off = 8;
        streamId = 0;
        nvCount = 0;
        endData = 0;
    }

    @Override
    public String toString() {
        if (c) {
            if (type == 6) {
                return "C PING " + associated;
            }
            return "C" + " S=" + streamId + (flags != 0 ? " F=" + flags : "")
                    + (version != 2 ? "  v" + version : "") + " t=" + type
                    + " L=" + endData + "/" + off;
        } else {
            return "D" + " S=" + streamId + (flags != 0 ? " F=" + flags : "")
                    + " L=" + endData + "/" + off;
        }
    }

    public int serializeHead() {
        if (c) {
            data[0] = (byte) 0x80;
            data[1] = (byte) version;
            data[2] = 0;
            data[3] = (byte) type;
            data[4] = (byte) flags;
            append24(data, 5, endData - 8);
            if (type == SpdyConnection.TYPE_SYN_STREAM) {
                append32(data, 8, streamId);
                append32(data, 12, associated);
                data[16] = 0; // TODO: priority
                data[17] = 0;
                return 18;
            } else if (type == SpdyConnection.TYPE_SYN_REPLY) {
                append32(data, 8, streamId);
                if (version == 2) {
                    data[12] = 0;
                    data[13] = 0;
                }
                return 14;
            } else if (type == SpdyConnection.TYPE_HEADERS) {
                append32(data, 8, streamId);
                if (version == 2) {
                    data[12] = 0;
                    data[13] = 0;
                }
                return 14;
            }
        } else {
            append32(data, 0, streamId);
            data[4] = (byte) flags;
            append24(data, 5, endData - 8);
        }
        return 8;
    }

    public boolean parse(int ver) {
        endData = 0;
        streamId = 0;
        nvCount = 0;

        int b0 = data[0] & 0xFF;
        if (b0 < 128) {
            // data frame
            c = false;
            streamId = read32(data, 0);
            version = ver;
        } else {
            c = true;
            b0 -= 128;
            version = ((b0 << 8) | data[1] & 0xFF);
            if (version != ver) {
                if (ver != 0) { // 0 on first frame
                    return false;
                }
            }
            b0 = data[2] & 0xFF;
            type = ((b0 << 8) | (data[3] & 0xFF));
        }

        flags = data[4] & 0xFF;
        for (int i = 5; i < 8; i++) {
            b0 = data[i] & 0xFF;
            endData = endData << 8 | b0;
        }

        // size will represent the end of the data ( header is held in same
        // buffer)
        endData += 8;

        return true;
    }

    public boolean isHalfClose() {
        return (flags & SpdyConnection.FLAG_FIN) != 0;
    }

    public void halfClose() {
        flags = SpdyConnection.FLAG_FIN;
    }

    public boolean closed() {
        return (flags & SpdyConnection.FLAG_FIN) != 0;
    }

    static void append24(byte[] buff, int off, int v) {
        buff[off++] = (byte) ((v & 0xFF0000) >> 16);
        buff[off++] = (byte) ((v & 0xFF00) >> 8);
        buff[off++] = (byte) ((v & 0xFF));
    }

    static void append32(byte[] buff, int off, int v) {
        buff[off++] = (byte) ((v & 0xFF000000) >> 24);
        buff[off++] = (byte) ((v & 0xFF0000) >> 16);
        buff[off++] = (byte) ((v & 0xFF00) >> 8);
        buff[off++] = (byte) ((v & 0xFF));
    }

    public void append32(int v) {
        makeSpace(4);
        data[off++] = (byte) ((v & 0xFF000000) >> 24);
        data[off++] = (byte) ((v & 0xFF0000) >> 16);
        data[off++] = (byte) ((v & 0xFF00) >> 8);
        data[off++] = (byte) ((v & 0xFF));
    }

    private void append16(int v) {
        makeSpace(2);
        data[off++] = (byte) ((v & 0xFF00) >> 8);
        data[off++] = (byte) ((v & 0xFF));
    }

    /**
     *  Update the name/value pair count before sending.
     *  Headers can be added at any time, no need to know the count
     *  before.
     *  
     * @param nvPos offset where nv count is stored based on type of frame 
     */
    void fixNV(int nvPos) {
        if (version == 3) {
            data[nvPos++] = 0;
            data[nvPos++] = 0;
        }
        data[nvPos++] = (byte) ((nvCount & 0xFF00) >> 8);
        data[nvPos] = (byte) ((nvCount & 0xFF));
    }

    public void append(byte[] buf, int soff, int len) {
        makeSpace(len + off);
        System.arraycopy(buf, soff, data, off, len);
        off += len;
    }

    /** 
     * Append a string length or nv/pair count. 2B in v2, 4B in v3.
     */
    public void appendCount(int len) {
        if (version == 2) {
            append16(len);
        } else {
            append32(len);
        }
    }
    
    public void headerValue(byte[] buf, int soff, int len) {
        makeSpace(len + 4);
        appendCount(len);
        System.arraycopy(buf, soff, data, off, len);
        off += len;
    }

    /**
     * Serialize the header name. For special headers use v3 syntax.
     */
    public void headerName(byte[] buf, int soff, int len) {
        // if it's the first header, leave space for extra params and NV count.
        // they'll be filled in by send.
        if (buf[soff] == ':' && version == 2) {
            // Adjust for v2 special header names. Will go away when v2 is removed
            soff++; // v2 uses "status", "version"
            if (buf[soff] == 'p' && buf[soff + 1] == 'a') { // th
                buf = URL;
                soff = 0;
                len = 3;
            }
            if (buf[soff] == 'h' && buf[soff + 1] == 'o') { // st
                return; // not used
            }
        }
        if (off == 8) {
            if (type == SpdyConnection.TYPE_SYN_REPLY) {
                off = version == 3 ? 16 : 18;
            } else if (type == SpdyConnection.TYPE_SYN_STREAM) {
                off = version == 3 ? 22 : 20;
            } else if (type != SpdyConnection.TYPE_HEADERS) {
                off = version == 3 ? 16 : 18;
            } else {
                throw new RuntimeException("Wrong frame type");
            }
        }
        nvCount++;
        headerValue(buf, soff, len);
    }

    public void addHeader(String name, String value) {
        byte[] nameB = name.getBytes();
        headerName(nameB, 0, nameB.length);
        nameB = value.getBytes();
        headerValue(nameB, 0, nameB.length);
    }

    public void addHeader(byte[] nameB, String value) {
        headerName(nameB, 0, nameB.length);
        nameB = value.getBytes();
        headerValue(nameB, 0, nameB.length);
    }

    public void addHeader(byte[] nameB, byte[] valueB) {
        headerName(nameB, 0, nameB.length);
        headerValue(valueB, 0, valueB.length);
    }

    public void getHeaders(Map<String, String> resHeaders) {
        for (int i = 0; i < nvCount; i++) {
            int len = readCount();
            String n = new String(data, off, len, SpdyStream.UTF8);
            advance(len);
            len = readCount();
            String v = new String(data, off, len, SpdyStream.UTF8);
            advance(len);
            resHeaders.put(n, v);
        }
    }


    // TODO: instead of that, use byte[][]
    void makeSpace(int len) {
        if (len < 256) {
            len = 256;
        }
        if (data == null) {
            data = new byte[len];
            return;
        }
        int newEnd = off + len;

        if (data.length < newEnd) {
            byte[] tmp = new byte[newEnd];
            System.arraycopy(data, 0, tmp, 0, off);
            data = tmp;
        }

    }

    /**
     *  16 for v2, 32 for v3
     */
    public int readCount() {
        if (version == 2) {
            return read16();
        } else {
            return read32();
        }
    }

    public int read16() {
        int res = data[off++] & 0xFF;
        return res << 8 | (data[off++] & 0xFF);
    }

    int readInt() {
        int res = 0;
        for (int i = 0; i < 4; i++) {
            int b0 = data[off++] & 0xFF;
            res = res << 8 | b0;
        }
        return res;
    }

    int read24() {
        int res = 0;
        for (int i = 0; i < 3; i++) {
            int b0 = data[off++] & 0xFF;
            res = res << 8 | b0;
        }
        return res;
    }

    int read32(byte[] data, int off) {
        int res = 0;
        for (int i = 0; i < 4; i++) {
            int b0 = data[off++] & 0xFF;
            res = res << 8 | b0;
        }
        return res;
    }

    int read32() {
        int res = 0;
        for (int i = 0; i < 4; i++) {
            int b0 = data[off++] & 0xFF;
            res = res << 8 | b0;
        }
        return res;
    }

    public int readByte() {
        return data[off++] & 0xFF;
    }

    public int remaining() {
        return endData - off;
    }

    public void advance(int cnt) {
        off += cnt;
    }

    public boolean isData() {
        return !c;
    }
}
