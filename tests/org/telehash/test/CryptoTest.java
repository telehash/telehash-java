/**
 * 
 */
package org.telehash.test;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Identity;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.RSAPrivateKey;
import org.telehash.crypto.RSAPublicKey;

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
    public void testRSAPublicKeyEncodeDecode() throws Exception {
        // generate a fresh identity
        Identity identity = mCrypto.generateIdentity();

        // DER-encode the public key
        RSAPublicKey publicKey = identity.getPublicKey();
        byte[] publicKeyBytes = publicKey.getDEREncoded();
        String publicKeyHex = Util.bytesToHex(publicKeyBytes);
        
        // DER-decode the public key
        byte[] publicKeyBytes2 = Util.hexToBytes(publicKeyHex);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKeyBytes2));
        RSAPublicKey publicKey2 = mCrypto.decodeRSAPublicKey(publicKeyBytes2);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKey2.getDEREncoded()));
    }

    @Test
    public void testRSAPrivateKeyEncodeDecode() throws Exception {
        // generate a fresh identity
        Identity identity = mCrypto.generateIdentity();

        // DER-encode the private key
        RSAPrivateKey privateKey = identity.getPrivateKey();
        byte[] privateKeyBytes = privateKey.getDEREncoded();
        String privateKeyHex = Util.bytesToHex(privateKeyBytes);

        // DER-decode the private key
        byte[] privateKeyBytes2 = Util.hexToBytes(privateKeyHex);
        assertEquals(privateKeyHex, Util.bytesToHex(privateKeyBytes2));
        RSAPrivateKey privateKey2 = mCrypto.decodeRSAPrivateKey(privateKeyBytes2);
        assertEquals(privateKeyHex, Util.bytesToHex(privateKey2.getDEREncoded()));
    }
    
    @Test
    public void testRSAEncryptDecrypt() throws Exception {
        // generate a fresh identity
        Identity identity = mCrypto.generateIdentity();
        
        // cycle keys through an encode/decode cycle to validate that
        // those methods aren't losing information necessary for the
        // encryption/decryption.  (The test*EncodeDecode() methods
        // above only verify consistency, not correctness.)
        RSAPublicKey publicKey = mCrypto.decodeRSAPublicKey(
                Util.hexToBytes(
                        Util.bytesToHex(
                                identity.getPublicKey().getDEREncoded()
                        )
                )
        );
        RSAPrivateKey privateKey = mCrypto.decodeRSAPrivateKey(
                Util.hexToBytes(
                        Util.bytesToHex(
                                identity.getPrivateKey().getDEREncoded()
                        )
                )
        );

        // encrypt
        byte[] cipherText = mCrypto.encryptRSA(publicKey, TEST_MESSAGE.getBytes("UTF-8"));
        // decrypt
        byte[] clearText = mCrypto.decryptRSA(privateKey, cipherText);
        String clearTextString = new String(clearText, "UTF-8");

        assertEquals(clearTextString, TEST_MESSAGE);
    }
    
}
