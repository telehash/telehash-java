package org.telehash.test;
import static org.junit.Assert.*;

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

}
