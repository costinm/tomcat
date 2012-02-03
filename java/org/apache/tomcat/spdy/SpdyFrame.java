/*
 */
package org.apache.tomcat.spdy;

public class SpdyFrame {
    public int associated;

    byte[] head = new byte[18]; // head + syn_reply top
    
    int flags;

    public int size;

    boolean c; // for control

    int version;

    int type;

    int streamId; // for data
    
    public byte[] data;
    public int off;

    public int nvCount;
    
    private static String[] TYPES = {};

    public String toString() {
        if (c) {
            if (type == 6) {
                return "C PING " + read32(data, 0);
            }
            return "C" + 
                " S=" + streamId +   
                (flags != 0 ? " F=" + flags: "") +
                (version != 2 ? "  v" + version: "") + 
                " t=" + type + 
                " L=" + size +
                "/" + off;
        } else {
            return "D" + 
                    " S=" + streamId +
                    (flags != 0 ? " F=" + flags: "") +
                    " L=" + size + "/" + off;
        }
     }
    
    public int serializeHead() {
        if (c) {
            head[0] = (byte) 0x80;
            head[1] = 2;
            head[2] = 0;
            head[3] = (byte) type;
            head[4] = (byte) flags;
            if (type == SpdyFramer.TYPE_SYN_STREAM) {
                append24(head, 5, size + 10);                
                append32(head, 8, streamId);
                append32(head, 12, associated);
                head[16] = 0;
                head[17] = 0;
                return 18;
            } else if (type == SpdyFramer.TYPE_SYN_REPLY) {
                append24(head, 5, size + 6);                
                append32(head, 8, streamId);
                head[12] = 0;
                head[13] = 0;
                return 14;
            } else {
                append24(head, 5, size);                
            }
        } else {
            append32(head, 0, streamId);
            head[4] = (byte) flags;
            append24(head, 5, size);            
        }
        return 8;
    }

    public boolean parse() {
        size = 0;
        streamId = 0;
        nvCount = 0;
        off = 0;
        int b0 = head[0] & 0xFF;
        if (b0 < 128) {
            // data frame 
            c = false;
            streamId = b0;
            streamId = read32(head, 0);
        } else {
            c = true;
            b0 -= 128;
            version = ((b0 << 8) | head[1] & 0xFF);
            if (version > 2) {
                return false;
            }
            b0 = head[2] & 0xFF;
            type = ((b0 << 8) | (head[3] & 0xFF));
        }

        flags = head[4] & 0xFF;
        for (int i = 5; i < 8; i++) {
            b0 = head[i] & 0xFF;
            size = size << 8 | b0;
        }
        
        return true;
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

    public void append16(int v) {
        makeSpace(2);
        data[off++] = (byte) ((v & 0xFF00) >> 8);
        data[off++] = (byte) ((v & 0xFF));
    }
    
    public void append(byte[] buf, int soff, int len) {
        makeSpace(len);
        System.arraycopy(buf, soff, data, off, len);
        off += len;
    }

    public void appendString(byte[] buf, int soff, int len) {
        makeSpace(len + 4);
        append16(len);
        System.arraycopy(buf, soff, data, off, len);
        off += len;
    }
    
    // TODO: instead of that, use byte[][]
    private void makeSpace(int len) {
        if (len < 256) {
            len = 256;
        }
        if (data == null) {
            data = new byte[len];
            return;
        }
        if (data.length - off < len) {
            byte[] tmp = new byte[data.length + len - off];
            System.arraycopy(data, 0, tmp, 0, off);
            data = tmp;
        }
            
    }

    public int readShort() {
        int res = data[off++];
        return res << 8 | data[off++];
    }

    int readInt() {
        int res = 0;
        for (int i = 0; i < 4; i++) {
            int b0 = data[off++];
            res = res << 8 | b0;
        }
        return res;
    }

    int read24() {
        int res = 0;
        for (int i = 0; i < 3; i++) {
            int b0 = data[off++];
            res = res << 8 | b0;
        }
        return res;
    }

    int read32(byte[] data, int off) {
        int res = 0;
        for (int i = 0; i < 4; i++) {
            int b0 = data[off++];
            res = res << 8 | b0;
        }
        return res;
    }

    int read32() {
        int res = 0;
        for (int i = 0; i < 4; i++) {
            int b0 = data[off++];
            res = res << 8 | b0;
        }
        return res;
    }

    public byte readByte() {
        return data[off++];
    }
    
    public int remaining() {
        return size - off;
    }
    
    public void advance(int cnt) {
        off += cnt;
    }
}