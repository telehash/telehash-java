package org.telehash.test;

import static org.junit.Assert.*;

import java.net.InetAddress;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.network.InetPath;
import org.telehash.network.Path;
import org.telehash.network.Network;

public class NetworkTest {
    
    private Network mNetwork = Util.getNetworkInstance();

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }
        
    class ParsePathTest {
        String string;
        byte[] address;
        int port;
        public ParsePathTest(String string, byte[] address, int port) {
            this.string = string;
            this.address = address;
            this.port = port;
        }
        public ParsePathTest(String string) {
            // represent an invalid string
            this.string = string;
            this.address = null;
            this.port = 0;
        }
        public void test() throws Exception {
            // parse
            Path path;
            try {
                path = mNetwork.parsePath(string);
            } catch (TelehashException e) {
                if (this.address == null) {
                    // failure expected.
                    return;
                } else {
                    throw e;
                }
            }
            if (this.address == null) {
                fail("parse failure expected but didn't happen.");
            }
            
            // basic tests
            assertNotNull(path);
            assertTrue(path instanceof InetPath);
            InetPath inetPath = (InetPath)path;
            InetAddress inetAddress = inetPath.getAddress();
            assertNotNull(inetAddress);
            assertTrue(inetPath.getPort() > 0);

            // accuracy tests
            assertArrayEquals(inetAddress.getAddress(), address);
            assertTrue(inetPath.getPort() == port);
        }
    };
    
    ParsePathTest[] parsePathTests = new ParsePathTest[] {
        new ParsePathTest("inet:10.0.0.1/4242", new byte[]{10,0,0,1}, 4242),
        new ParsePathTest("inet:192.168.1.100/512", new byte[]{(byte)192,(byte)168,1,100}, 512),
        new ParsePathTest(
                "inet:2001:0db8:85a3:0000:0000:8a2e:0370:7334/1234",
                new byte[]{
                        0x20, 0x01, 0x0d, (byte)0xb8, (byte)0x85, (byte)0xa3, 0x00, 0x00,
                        0x00, 0x00, (byte)0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34
                },
                1234
        ),
        new ParsePathTest(
                "inet:2001::1/2345",
                new byte[]{
                        0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
                },
                2345
        ),        
    };
    
    @Test
    public void testParsePath() throws Exception {
        for (ParsePathTest test : parsePathTests) {
            test.test();
        }
    }

}
