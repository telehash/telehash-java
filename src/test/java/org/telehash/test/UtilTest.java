package org.telehash.test;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Util;


public class UtilTest {

    private static final String TEST_HEX_STRING = "00FF7f8081abab";
    private static final byte[] TEST_BYTES = {
        0x00, (byte)0xFF, 0x7F, (byte)0x80, (byte)0x81, (byte)0xAB, (byte)0xAB
    };

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testHexToBytes() {
        byte[] buffer = Util.hexToBytes(TEST_HEX_STRING);
        assertArrayEquals(buffer, TEST_BYTES);
    }

    @Test
    public void testBytesToHex() {
        String hex = Util.bytesToHex(TEST_BYTES);
        assertEquals(hex, TEST_HEX_STRING.toLowerCase());
    }

    private static final String[][] BASE64_TESTS = {
        {"", ""},
        {"a", "YQ=="},
        {"ab", "YWI="},
        {"abc", "YWJj"},
        {"abcd", "YWJjZA=="},
        {"abcde", "YWJjZGU="},
        {"abcdef", "YWJjZGVm"},
        {"abcdefg", "YWJjZGVmZw=="},
        {   "This is a test.  This is only a test.",
            "VGhpcyBpcyBhIHRlc3QuICBUaGlzIGlzIG9ubHkgYSB0ZXN0Lg=="
        }
    };
    private static final Object[][] BASE64_BINARY_TESTS = {
        {new byte[] {}, ""},
        {new byte[] {0x01}, "AQ=="},
        {new byte[] {0x01, 0x02}, "AQI="},
        {new byte[] {0x01, 0x02, 0x03}, "AQID"},
        {new byte[] {0x01, 0x02, 0x03, 0x04}, "AQIDBA=="},
        {new byte[] {(byte)0x81}, "gQ=="},
        {new byte[] {(byte)0x81, (byte)0x82}, "gYI="},
        {new byte[] {(byte)0x81, (byte)0x82, (byte)0x83}, "gYKD"},
        {new byte[] {(byte)0x81, (byte)0x82, (byte)0x83, (byte)0x84}, "gYKDhA=="},
        {new byte[] {(byte)0xFF}, "/w=="},
        {new byte[] {(byte)0xFF, (byte)0xFF}, "//8="},
        {new byte[] {(byte)0xFF, (byte)0xFF, (byte)0xFF}, "////"},
        {new byte[] {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF}, "/////w=="},
    };
    private static final Object[][] BASE64_DECODE_TESTS = {
        // invalid character
        { "ABCDE?FG", null },
        // no padding - needs 1 char of padding
        { "YWJjZGU", "abcde" },
        // no padding - needs 2 chars of padding
        {
                "VGhpcyBpcyBhIHRlc3QuICBUaGlzIGlzIG9ubHkgYSB0ZXN0Lg",
                "This is a test.  This is only a test."
        }
    };

    @Test
    public void testBase64EncodeDecode() throws Exception {
        for (String[] test : BASE64_TESTS) {
            String message = test[0];
            String expectedEncoding = test[1];

            String encoding = Util.base64Encode(message.getBytes("UTF-8"));
            assertEquals(expectedEncoding, encoding);
            byte[] decodedBytes = Util.base64Decode(encoding);
            assertNotNull(decodedBytes);
            String decoding = new String(decodedBytes, "UTF-8");
            assertEquals(message, decoding);
        }

        for (Object[] test : BASE64_BINARY_TESTS) {
            byte[] message = (byte[]) test[0];
            String expectedEncoding = (String) test[1];

            String encoding = Util.base64Encode(message);
            assertEquals(expectedEncoding, encoding);
            byte[] decoding = Util.base64Decode(encoding);
            assertNotNull(decoding);
            assertArrayEquals(message, decoding);
        }

        for (Object[] test : BASE64_DECODE_TESTS) {
            String base64 = (String)test[0];
            byte[] expectedDecoding;
            if (test[1] instanceof String) {
                expectedDecoding = ((String)test[1]).getBytes("UTF-8");
            } else {
                expectedDecoding = (byte[])test[1];
            }

            byte[] decoding = Util.base64Decode(base64);
            if (expectedDecoding == null) {
                assertNull(decoding);
            } else {
                assertArrayEquals(expectedDecoding, decoding);
            }
        }
    }
}
