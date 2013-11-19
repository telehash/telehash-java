/**
 * 
 */
package org.telehash.test;

import static org.junit.Assert.*;

import java.security.PublicKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Identity;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;

public class CryptoTest {
    
    private static final String TEST_MESSAGE = "This is a test.";
    private static final String TEST_MESSAGE_DIGEST =
            "a8a2f6ebe286697c527eb35a58b5539532e9b3ae3b64d4eb0a46fb657b41562c";

    private Crypto mCrypto;
    
    @Before
    public void setUp() throws Exception {
        mCrypto = Util.getCryptoInstance();
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testSha256Digest() throws Exception {
        byte[] digest = mCrypto.sha256Digest(TEST_MESSAGE.getBytes("UTF-8"));
        assertArrayEquals(digest, Util.hexToBytes(TEST_MESSAGE_DIGEST));
    }

    @Test
    public void testDEREncodeDecode() throws Exception {
        // generate a fresh identity
        Identity identity = mCrypto.generateIdentity();

        // DER-encode the public key
        PublicKey publicKey = identity.getPublicKey();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String publicKeyHex = Util.bytesToHex(publicKeyBytes);
        
        // DER-decode the public key
        byte[] publicKeyBytes2 = Util.hexToBytes(publicKeyHex);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKeyBytes2));
        PublicKey publicKey2 = mCrypto.derToRSAPublicKey(publicKeyBytes2);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKey2.getEncoded()));
    }
}
