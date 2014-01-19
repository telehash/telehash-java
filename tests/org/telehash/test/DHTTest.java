package org.telehash.test;

import static org.junit.Assert.*;

import java.net.InetAddress;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.HashName;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.impl.CryptoImpl;
import org.telehash.dht.DHT;
import org.telehash.network.InetPath;
import org.telehash.network.Path;
import org.telehash.network.Network;

public class DHTTest {
    
    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }
        
    private class DistanceTest {
        private HashName mOrigin;
        private HashName mRemote;
        private int mDistance;
        public DistanceTest(byte[] originBytes, byte[] remoteBytes, int distance) {
            mOrigin = new HashName(Util.fixedSizeBytes(originBytes, HashName.SIZE));
            mRemote = new HashName(Util.fixedSizeBytes(remoteBytes, HashName.SIZE));
            mDistance = distance;
        }
        public DistanceTest(int[] originBytes, int[] remoteBytes, int distance) {
            mOrigin = new HashName(padBytes(originBytes));
            mRemote = new HashName(padBytes(remoteBytes));
            mDistance = distance;
        }
        private byte[] padBytes(int[] ints) {
            byte[] bytes = new byte[ints.length];
            for (int i=0; i<ints.length; i++) {
                bytes[i] = (byte)ints[i];
            }
            return Util.fixedSizeBytes(bytes, HashName.SIZE);
        }
        public void test() {
            System.out.print("distance "+mOrigin+" -> "+mRemote+" = ");
            int measuredDistance = DHT.logDistance(mOrigin, mRemote);
            System.out.println(measuredDistance+" (expect: "+mDistance+")");
            assertEquals(mDistance, measuredDistance);
        }
    }
    DistanceTest[] mDistanceTests = new DistanceTest[] {
            new DistanceTest(
                    new byte[] {1,2,3},
                    new byte[] {1,2,3},
                    -1 // indicates identical hashnames
            ),
            new DistanceTest(
                    new byte[] {0},
                    new byte[] {1},
                    0
            ),
            new DistanceTest(
                    new byte[] {1},
                    new byte[] {2},
                    1
            ),
            new DistanceTest(
                    new byte[] {2},
                    new byte[] {3},
                    0
            ),
            new DistanceTest(
                    new int[] {0xFF},
                    new int[] {0xFE},
                    0
            ),
            new DistanceTest(
                    new int[] {0xFF},
                    new int[] {0xF0},
                    3
            ),
            new DistanceTest(
                    new int[] {0xFF, 0xFF},
                    new int[] {0xFF, 0xF0},
                    3
            ),
            new DistanceTest(
                    new int[] {0xFF, 0xFF},
                    new int[] {0x00, 0xFF},
                    15
            ),
            new DistanceTest(
                    new int[] {0xFF, 0xFF},
                    new int[] {0x0F, 0xFF},
                    15
            ),
            new DistanceTest(
                    new int[] {0x1F, 0xFF},
                    new int[] {0x0F, 0xFF},
                    12
            ),
    };
    
    @Test
    public void testDistance() throws Exception {
        for (DistanceTest test : mDistanceTests) {
            test.test();
        }
    }
    
    private static final int NUM_ORIGINS = 16;
    private static final int NUM_RANDOMS = 16;
    
    @Test
    public void testRandomHashName() throws Exception {
        Crypto crypto = new CryptoImpl();
        for (int x=0; x<NUM_ORIGINS; x++) {
            HashName origin = new HashName(crypto.getRandomBytes(HashName.SIZE));
            for (int bucket=0; bucket<256; bucket++) {
                for (int y=0; y<NUM_RANDOMS; y++) {
                    HashName random = DHT.getRandomHashName(origin, bucket);
                    int measuredDistance = DHT.logDistance(origin, random);
                    /*
                    System.out.print("random("+origin+", "+bucket+") = ");
                    System.out.println(random+" ("+measuredDistance+")");
                    */
                    assertEquals(bucket, measuredDistance);
                }
            }
        }
    }

}
