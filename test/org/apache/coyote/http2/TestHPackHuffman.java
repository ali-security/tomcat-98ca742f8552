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
package org.apache.coyote.http2;

import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;

public class TestHPackHuffman {

    /*
     * '{' has a 15 bit Huffman code. Prior to resetting the EOS bit count when a character is decoded, the 7 trailing
     * one bits of that code plus the padding were counted as more than 7 bits of EOS padding and the value was
     * rejected. This specific String exposed that edge case. (A lone "{" can't be used as its Huffman encoding is
     * longer than the original so HPackHuffman.encode() declines to encode it.)
     */
    @Test
    public void testValueLeftBrace() throws Exception {
        doTestRoundTrip("x-value{");
    }


    @Test
    public void testValueEndsWithLeftBrace() throws Exception {
        doTestRoundTrip("value{");
    }


    @Test
    public void testValueAllFieldVChars() throws Exception {
        StringBuilder sb = new StringBuilder();
        for (char c = 0x21; c < 0x7F; c++) {
            sb.append(c);
        }
        doTestRoundTrip(sb.toString());
    }


    private void doTestRoundTrip(String data) throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(1024);
        Assert.assertTrue(HPackHuffman.encode(buf, data, false));
        buf.flip();
        // Skip the length byte(s)
        byte first = buf.get();
        Assert.assertEquals((byte) 0x80, (byte) (first & 0x80));
        int length = first & 0x7F;
        if (length == 0x7F) {
            int m = 0;
            int b;
            length = 0x7F;
            do {
                b = buf.get() & 0xFF;
                length += (b & 0x7F) << m;
                m += 7;
            } while ((b & 0x80) != 0);
        }
        Assert.assertEquals(length, buf.remaining());

        StringBuilder target = new StringBuilder();
        HPackHuffman.decode(buf, buf.remaining(), target);

        Assert.assertEquals("Value changed after encode/decode roundtrip", data, target.toString());
    }
}
