/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.security;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.buf.ByteChunk;

public class TestConstantTime {

    @Test
    public void testStringEquals() {
        Assert.assertTrue(ConstantTime.equals("secret", "secret", false));
        Assert.assertTrue(ConstantTime.equals("secret", new String("secret"), false));
        Assert.assertTrue(ConstantTime.equals("secret", "secret", true));
    }


    @Test
    public void testStringSameInstance() {
        String s = "secret";
        Assert.assertTrue(ConstantTime.equals(s, s, false));
    }


    @Test
    public void testStringCase() {
        Assert.assertFalse(ConstantTime.equals("secret", "SECRET", false));
        Assert.assertFalse(ConstantTime.equals("SECRET", "secret", false));
        Assert.assertTrue(ConstantTime.equals("secret", "SECRET", true));
        Assert.assertTrue(ConstantTime.equals("SeCrEt", "sEcReT", true));
    }


    @Test
    public void testStringNearMiss() {
        // Same length, single character difference at the start, middle and end
        Assert.assertFalse(ConstantTime.equals("secret", "xecret", false));
        Assert.assertFalse(ConstantTime.equals("secret", "secXet", false));
        Assert.assertFalse(ConstantTime.equals("secret", "secrex", false));
        Assert.assertFalse(ConstantTime.equals("secret", "secrex", true));
    }


    @Test
    public void testStringDifferentLength() {
        // Prefix of the expected value
        Assert.assertFalse(ConstantTime.equals("secre", "secret", false));
        Assert.assertFalse(ConstantTime.equals("s", "secret", false));
        // Expected value followed by trailing data
        Assert.assertFalse(ConstantTime.equals("secretX", "secret", false));
        Assert.assertFalse(ConstantTime.equals("secretsecret", "secret", false));
        // Trailing data that matches the first character (index wraps to 0 for the extra characters)
        Assert.assertFalse(ConstantTime.equals("secrets", "secret", false));
        Assert.assertFalse(ConstantTime.equals("aaaa", "a", false));
        Assert.assertFalse(ConstantTime.equals("a", "aaaa", false));
    }


    @Test
    public void testStringEmpty() {
        Assert.assertTrue(ConstantTime.equals("", "", false));
        Assert.assertTrue(ConstantTime.equals("", new String(""), true));
        Assert.assertFalse(ConstantTime.equals("", "secret", false));
        Assert.assertFalse(ConstantTime.equals("secret", "", false));
    }


    @Test
    public void testStringNull() {
        Assert.assertTrue(ConstantTime.equals((String) null, (String) null, false));
        Assert.assertFalse(ConstantTime.equals(null, "secret", false));
        Assert.assertFalse(ConstantTime.equals("secret", null, false));
        Assert.assertFalse(ConstantTime.equals(null, "", false));
        Assert.assertFalse(ConstantTime.equals("", null, false));
    }


    @Test
    public void testByteChunkEquals() {
        Assert.assertTrue(ConstantTime.equals(createByteChunk("secret"), "secret"));
    }


    @Test
    public void testByteChunkNonZeroStart() {
        // The value being compared is in the middle of a larger buffer as it is for an AJP message
        byte[] buf = "XYZsecretUVW".getBytes(StandardCharsets.ISO_8859_1);
        ByteChunk bc = new ByteChunk();
        bc.setBytes(buf, 3, 6);

        Assert.assertTrue(ConstantTime.equals(bc, "secret"));
        Assert.assertFalse(ConstantTime.equals(bc, "XYZsec"));
        Assert.assertFalse(ConstantTime.equals(bc, "secretUVW"));
        Assert.assertFalse(ConstantTime.equals(bc, "secrex"));
        Assert.assertFalse(ConstantTime.equals(bc, "secre"));
    }


    @Test
    public void testByteChunkNearMiss() {
        ByteChunk bc = createByteChunk("secret");
        Assert.assertFalse(ConstantTime.equals(bc, "xecret"));
        Assert.assertFalse(ConstantTime.equals(bc, "secXet"));
        Assert.assertFalse(ConstantTime.equals(bc, "secrex"));
        // Comparison is case sensitive
        Assert.assertFalse(ConstantTime.equals(bc, "SECRET"));
    }


    @Test
    public void testByteChunkDifferentLength() {
        Assert.assertFalse(ConstantTime.equals(createByteChunk("secre"), "secret"));
        Assert.assertFalse(ConstantTime.equals(createByteChunk("s"), "secret"));
        Assert.assertFalse(ConstantTime.equals(createByteChunk("secretX"), "secret"));
        Assert.assertFalse(ConstantTime.equals(createByteChunk("secrets"), "secret"));
        Assert.assertFalse(ConstantTime.equals(createByteChunk("aaaa"), "a"));
        Assert.assertFalse(ConstantTime.equals(createByteChunk("a"), "aaaa"));
    }


    @Test
    public void testByteChunkHighBytes() {
        // Bytes are treated as unsigned (ISO-8859-1) values
        ByteChunk bc = new ByteChunk();
        bc.setBytes(new byte[] { 'a', (byte) 0xE9, 'b' }, 0, 3);
        Assert.assertTrue(ConstantTime.equals(bc, "a\u00e9b"));
        // A char that only matches the sign extended byte must not be treated as equal
        Assert.assertFalse(ConstantTime.equals(bc, "a\uffe9b"));
        Assert.assertFalse(ConstantTime.equals(bc, "a\u01e9b"));
        // 'i' is 0x69 which is 0xE9 with the high bit cleared
        Assert.assertFalse(ConstantTime.equals(bc, "aib"));
        Assert.assertFalse(ConstantTime.equals(bc, "aeb"));
    }


    @Test
    public void testByteChunkHighBytesNonZeroStart() {
        ByteChunk bc = new ByteChunk();
        bc.setBytes(new byte[] { 'x', 'x', (byte) 0xFF, (byte) 0x80, 'z', 'y' }, 2, 3);
        Assert.assertTrue(ConstantTime.equals(bc, "\u00ff\u0080z"));
        Assert.assertFalse(ConstantTime.equals(bc, "\uffff\uff80z"));
        Assert.assertFalse(ConstantTime.equals(bc, "xx\u00ff"));
    }


    @Test
    public void testByteChunkEmpty() {
        Assert.assertTrue(ConstantTime.equals(createByteChunk(""), ""));
        Assert.assertFalse(ConstantTime.equals(createByteChunk(""), "secret"));
        Assert.assertFalse(ConstantTime.equals(createByteChunk("secret"), ""));
    }


    @Test
    public void testByteChunkNoBuffer() {
        // A ByteChunk that has never been set must not match a non-empty value (and must not throw)
        Assert.assertFalse(ConstantTime.equals(new ByteChunk(), "secret"));
    }


    @Test
    public void testByteChunkNull() {
        Assert.assertTrue(ConstantTime.equals((ByteChunk) null, (String) null));
        Assert.assertFalse(ConstantTime.equals((ByteChunk) null, "secret"));
        Assert.assertFalse(ConstantTime.equals(createByteChunk("secret"), (String) null));
    }


    @Test
    public void testByteArrayEquals() {
        Assert.assertTrue(ConstantTime.equals(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 3 }));
        Assert.assertTrue(ConstantTime.equals(new byte[0], new byte[0]));
        Assert.assertFalse(ConstantTime.equals(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 4 }));
        Assert.assertFalse(ConstantTime.equals(new byte[] { 1, 2, 3 }, new byte[] { 1, 2 }));
        Assert.assertFalse(ConstantTime.equals(new byte[] { 1, 2 }, new byte[] { 1, 2, 3 }));
        Assert.assertFalse(ConstantTime.equals(new byte[] { 1, 2, 3 }, new byte[0]));
    }


    private static ByteChunk createByteChunk(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.ISO_8859_1);
        ByteChunk bc = new ByteChunk();
        bc.setBytes(bytes, 0, bytes.length);
        return bc;
    }
}
