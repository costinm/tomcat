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

import org.apache.tomcat.jni.SSLExt;

import com.jcraft.jzlib.JZlib;
import com.jcraft.jzlib.ZStream;


/** 
 * The 'real' SPDY protocol - used by chrome and browsers, with SSL NPN 
 * extension and header compression.
 * 
 * The base class is intended for SPDY in a proxy environment, where SSL, 
 * NPN and compression are handled by a frontend proxy/load balancer.
 * 
 */
public class SpdyFramerNPN extends SpdyFramer {
    public static long DICT_ID = 3751956914L;
    // Make sure to use the latest from net/spdy/spdy_framer.cc, not from spec
    private static String SPDY_DICT_S = 
    "optionsgetheadpostputdeletetraceacceptaccept-charsetaccept-encodingaccept-" +
    "languageauthorizationexpectfromhostif-modified-sinceif-matchif-none-matchi" +
    "f-rangeif-unmodifiedsincemax-forwardsproxy-authorizationrangerefererteuser" +
    "-agent10010120020120220320420520630030130230330430530630740040140240340440" +
    "5406407408409410411412413414415416417500501502503504505accept-rangesageeta" +
    "glocationproxy-authenticatepublicretry-afterservervarywarningwww-authentic" +
    "ateallowcontent-basecontent-encodingcache-controlconnectiondatetrailertran" +
    "sfer-encodingupgradeviawarningcontent-languagecontent-lengthcontent-locati" +
    "oncontent-md5content-rangecontent-typeetagexpireslast-modifiedset-cookieMo" +
    "ndayTuesdayWednesdayThursdayFridaySaturdaySundayJanFebMarAprMayJunJulAugSe" +
    "pOctNovDecchunkedtext/htmlimage/pngimage/jpgimage/gifapplication/xmlapplic" +
    "ation/xhtmltext/plainpublicmax-agecharset=iso-8859-1utf-8gzipdeflateHTTP/1" +
    ".1statusversionurl ";
    
    public static byte[] SPDY_DICT = SPDY_DICT_S.getBytes();
    // C code uses this - not in the spec
    static {
        SPDY_DICT[SPDY_DICT.length - 1] = (byte) 0;
    }

    // Stream format: RFC1950
    // 1CMF 1FLG [4DICTID] DATA 4ADLER
    // CMF:  CINFO + CM (compression method). == x8
    // 78 == deflate with 32k window, i.e. max window
    
    // FLG: 2bit level, 1 bit FDICT, 5 bit FCHECK
    // Cx, Dx - no dict; Fx, Ex - dict ( for BEST_COMPRESSION )
    
    // Overhead: 6 bytes without dict, 10 with dict
    // data is encoded in blocks - there is a 'block end' marker and
    // 'last block'.
    
    // Flush: http://www.bolet.org/~pornin/deflate-flush.html
    // inflater needs about 9 bits 
    // Z_SYNC_FLUSH: send empty block, 00 00 FF FF - seems recomended
    // PPP can skip this - there is a record format on top
    // Z_PARTIAL_FLUSH: standard for SSH

    ZStream cStream;
    ZStream dStream;
    
    byte[] dict;
    long dictId;
    
    byte[] decompressBuffer;
    byte[] compressBuffer;
    
    
    SpdyFramerNPN(LightChannel socket) {
        super(socket);
        setDictionary(SPDY_DICT, DICT_ID);
    }
    
    public static boolean checkNPN(LightChannel socket) {
        byte[] npn = new byte[8];
        int npnLen = 0;
        try {
            long aprSocket = ((LightChannelApr) socket).socket;
            npnLen = SSLExt.getNPN(aprSocket, npn);
        } catch (Throwable t) {
            // ignore
            return false;
        }
        if (npnLen == 6 && npn[0] == 's' && npn[1] == 'p' && npn[2] == 'd'
                && npn[3] == 'y') {
            
            return true;
        }    
        return false;
    }
    
    public static boolean checkNPN(byte[] npn, int len) {
        // Quick check
        return npn[0] == 's';
    }
    
    public static void setNPN(long sslContext) {
        try {
            String npn = "spdy/2";
            byte[] spdyNPN = new byte[npn.length() + 2];
            System.arraycopy(npn.getBytes(), 0, spdyNPN, 1, npn.length());
            spdyNPN[0] = (byte) npn.length();
            spdyNPN[npn.length() + 1] = 0;        
            SSLExt.setNPN(sslContext, spdyNPN, spdyNPN.length);
        } catch (Throwable t) {
            log.warn("SPDY NPN not available");
        }        
    }
    
    
    
    public void recycle() {
        if (cStream == null) {
            return;
        }
        cStream.free();
        cStream = null;
        dStream.free();
        dStream = null;
    }
    
    public void init() {
        if (cStream != null) {
            return;
        }
        // can't call: cStream.free(); - will kill the adler, NPE
        cStream = new ZStream();
        // BEST_COMRESSION results in 256Kb per Deflate
        // 15 == default = 32k window
        cStream.deflateInit(JZlib.Z_BEST_SPEED, 10);
        
        dStream = new ZStream();
        dStream.inflateInit();

    }
    
    public SpdyFramerNPN setDictionary(byte[] dict, long id) {
        init();
        this.dict = dict;
        this.dictId = id;
        cStream.deflateSetDictionary(dict, dict.length);
        return this;
    }

//    public void compress(IOBuffer in, IOBuffer out) throws IOException {
//        init();
//        BBuffer bb = in.popFirst();
//        
//        while (bb != null) {
//            // TODO: only the last one needs flush
//
//            // TODO: size missmatches ?
//            compress(bb, out, false);
//            bb = in.popFirst();
//        }
//        
//        if (in.isClosedAndEmpty()) {
//            compressEnd(out);
//        }
//    }
//    
    @Override
    protected void compress(SpdyFrame frame) throws IOException {
        // TODO: only the last one needs flush
        // TODO: size missmatches ?
        init();
        int flush = JZlib.Z_PARTIAL_FLUSH;

        cStream.next_in = frame.data;
        cStream.next_in_index = 0;
        cStream.avail_in = frame.size;

        if (compressBuffer == null || compressBuffer.length < frame.size + 256) {
            compressBuffer = new byte[frame.size + 256];
        }
        int outOff = 0;
        while (true) {
            cStream.next_out = compressBuffer;
            cStream.next_out_index = outOff;
            cStream.avail_out = compressBuffer.length - outOff;

            int err = cStream.deflate(flush);
            check(err, cStream);
            outOff = cStream.next_out_index;
            
            byte[] tmp = frame.data;
            frame.data = compressBuffer;
            compressBuffer = tmp;
            if (cStream.avail_out > 0 || cStream.avail_in == 0) {
                break;
            }
         }
         frame.size = outOff;
        
//        if (last) {
//            compressEnd(out);
//        }
    }
//
//    private void compressEnd(IOBuffer out) throws IOException {
//        while (true) {
//            BBuffer outB = out.getAppendBuffer();
//            cStream.next_out = outB.array();
//        
//            cStream.next_out_index = outB.end();
//            cStream.avail_out = outB.appendSpace();
//            cStream.deflate(JZlib.Z_FINISH);
//            cStream.deflateEnd();
//            
//            outB.end(cStream.next_out_index);
//            if (cStream.avail_out > 0) {
//                break;
//            }
//        }
//    }

    @Override
    protected void decompress(SpdyFrame frame) throws IOException {
        // stream id ( 4 ) + unused ( 2 ) 
        // nvCount is compressed in impl - spec is different
        init();
        
        dStream.next_in = frame.data;
        dStream.next_in_index = frame.off;
        dStream.avail_in = frame.size - frame.off;
        if (decompressBuffer == null || decompressBuffer.length < frame.size * 2) {
            decompressBuffer = new byte[frame.size * 2];
        }
        int tmpOff = 0;
        
        while (true) {
            dStream.next_out = decompressBuffer;
            dStream.next_out_index = tmpOff;
            dStream.avail_out = decompressBuffer.length - tmpOff;
            
            int err = dStream.inflate(JZlib.Z_SYNC_FLUSH);
            if (err == JZlib.Z_NEED_DICT && dict != null) {
                dStream.inflateSetDictionary(dict, dict.length);
                err = dStream.inflate(JZlib.Z_SYNC_FLUSH);
            }
            tmpOff = dStream.next_out_index;

            if (err == JZlib.Z_STREAM_END) {
                err = dStream.inflateEnd();
                check(err, dStream);
                // move in back, not consummed
                return;
            }
            check(err, dStream);

            if (dStream.avail_in == 0) {
                break;
            }
            // We need to grow the buffer
            byte[] b = new byte[decompressBuffer.length * 2];
            System.arraycopy(decompressBuffer, 0, b, 0, tmpOff);
            decompressBuffer = b;
        }
        
        // Done: replace frame.data[] ( swap actually to avoid allocs )
        byte[] tmp = frame.data;
        frame.data = decompressBuffer;
        decompressBuffer = tmp;
        frame.off = 0;
        frame.size = tmpOff;
    }
    
    private void check(int err, ZStream stream) throws IOException {
        if (err != JZlib.Z_OK) {
            throw new IOException(err + " " + stream.msg);
        }
    }
    
}

