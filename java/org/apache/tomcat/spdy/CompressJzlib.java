/*
 */
package org.apache.tomcat.spdy;

import java.io.IOException;

import org.apache.tomcat.spdy.SpdyFramer.CompressSupport;

import com.jcraft.jzlib.JZlib;
import com.jcraft.jzlib.ZStream;

public class CompressJzlib implements CompressSupport {
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
    

    public CompressJzlib() {
        setDictionary(SPDY_DICT, DICT_ID);
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
    
    public void setDictionary(byte[] dict, long id) {
        init();
        this.dict = dict;
        this.dictId = id;
        cStream.deflateSetDictionary(dict, dict.length);
    }
    
    // TODO: use per thread compressor.
    @Override
    public synchronized void compress(SpdyFrame frame, int start) throws IOException {
        // TODO: only the last one needs flush
        // TODO: size missmatches ?
        init();
        int flush = JZlib.Z_PARTIAL_FLUSH;

        cStream.next_in = frame.data;
        cStream.next_in_index = start;
        cStream.avail_in = frame.endData - start;

        if (compressBuffer == null || compressBuffer.length < frame.endData + 256) {
            compressBuffer = new byte[frame.endData + 256];
        }
        int outOff = start; // same position
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
         frame.endData = outOff;
        
//        if (last) {
//            compressEnd(out);
//        }
    }
    
    @Override
    public synchronized void decompress(SpdyFrame frame, int start) throws IOException {
        // stream id ( 4 ) + unused ( 2 ) 
        // nvCount is compressed in impl - spec is different
        init();
        
        dStream.next_in = frame.data;
        dStream.next_in_index = start;
        dStream.avail_in = frame.endData - start;
        if (decompressBuffer == null || decompressBuffer.length < frame.endData * 2) {
            decompressBuffer = new byte[frame.endData * 2];
        }
        int tmpOff = start;
        
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
        frame.off = start;
        frame.endFrame = tmpOff;
    }
    
    private void check(int err, ZStream stream) throws IOException {
        if (err != JZlib.Z_OK) {
            throw new IOException(err + " " + stream.msg);
        }
    }
    
}
