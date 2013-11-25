/**
 * 
 */
package org.telehash.test;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Identity;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.ECKeyPair;
import org.telehash.crypto.ECPublicKey;
import org.telehash.crypto.RSAPrivateKey;
import org.telehash.crypto.RSAPublicKey;

public class CryptoTest {
    
    private static final String TEST_MESSAGE = "This is a test.";
    private static final String TEST_MESSAGE_DIGEST =
            "a8a2f6ebe286697c527eb35a58b5539532e9b3ae3b64d4eb0a46fb657b41562c";
    
    private static final String IDENTITY_PUBLIC_KEY =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvv8h0XuJHXaUaQpBDFTA" +
            "e6Pj2evamzkTgA2QfYcMjcmRK4V+o7Kv54RvD02MQIGJGSEF2nsqKcE4MpseRWGB" +
            "PH3/mILG+ru30IxjKscIPwADHll8DOTkfez24XP5CvqNeXkoKV9/AgtYkrII4Kh/" +
            "P9qxREs/aPuov2JSlZAspznaj45SVodeStRzb1rQPM672AqednZ2PzD/WQFaLy/y" +
            "nBuEcKSeGSpyFyzXJF4sz8kietALRnoKjkAGNTyrrteYLRiPRa0ek/1kq7tZ6168" +
            "dhOxRQD4vZwh6wZm35eV1XlbllchvgtgCt10lXsSZhSKsb6/4TW2KlZtb8IaHCqt" +
            "lwIDAQAB";
    private static final String IDENTITY_PRIVATE_KEY =
            "MIIEowIBAAKCAQEAvv8h0XuJHXaUaQpBDFTAe6Pj2evamzkTgA2QfYcMjcmRK4V+" +
            "o7Kv54RvD02MQIGJGSEF2nsqKcE4MpseRWGBPH3/mILG+ru30IxjKscIPwADHll8" +
            "DOTkfez24XP5CvqNeXkoKV9/AgtYkrII4Kh/P9qxREs/aPuov2JSlZAspznaj45S" +
            "VodeStRzb1rQPM672AqednZ2PzD/WQFaLy/ynBuEcKSeGSpyFyzXJF4sz8kietAL" +
            "RnoKjkAGNTyrrteYLRiPRa0ek/1kq7tZ6168dhOxRQD4vZwh6wZm35eV1Xlbllch" +
            "vgtgCt10lXsSZhSKsb6/4TW2KlZtb8IaHCqtlwIDAQABAoIBABqR6YV31wpHPbwj" +
            "Fgt+GszYbtEZE282kHTm7ivYRrHO0agpSQXCzN+7N6v8UL+Ehar+Qg8zxRjL7WJ0" +
            "29AxEUZ2DMGNp9qnlJmpff4sdAQ3nzdwoWY1zWeLOIkCliml01qLtT+ULln9dBPs" +
            "OnnuVs1uQezLPwX+xGnjZrOxu9SDZQgud9CTuevDAqhkNgf1Br4JYjKPJjqGJc0M" +
            "WqCG/N4hrr6/D9lsek95v2ZH9uEP3M7P+v8oKIWzCYZ0ayoiIgwz1MrcE8cfjzxt" +
            "dbRf74+Goz+SkRWMmgmrwuPQENrBockY5DCL0fwrS/L0J7Ch6j+0/ZVk0n3hemC/" +
            "vO8hvfECgYEA89PunTzhxsw18NHouYtNaA3ay3AA02rAYgXE05NCZlsxXSNxHrGP" +
            "YwVBrfBr5B5On+wpZwnDVxVXkflUGAakZ9trafjpKFGTuLuqpjL7Wrannf4Ky5rP" +
            "mUh09o5ca3WSqPcwxlahHNoJKJeYfCVQ3KhnJFIxp/aZmWdTi4sp1z8CgYEAyIgH" +
            "Ju7PgBc7kx1LfuQv2Wr+e3J4pYGt5xzCDXMjrINyieeH8Z49MmUsI+UlNyvFirWa" +
            "YE8oUcKLa68esk3jYckZ+00/GbCkoNjEkzV9+Y9mmyz3HNGLxCCtq77MWG4KHmXn" +
            "rP2OMG8Z/JN9QiIOfJlpNI11x8JakjVbDPScK6kCgYEAmccfJdIA/zVKC9EHewXt" +
            "UuPyCv5ftvcL0Iac5WdpqE55aqlwrZAEw8nL65zHHv8yTVBPqGmS5nhSW4EpVWHT" +
            "DKFpNFPFESWqCgdqEBn1RvgN7OoM+u5vYdg91EZi6W8kiSYlf+GhCSZGQnChviJ2" +
            "xkP7kP+5y5oOs55kJY0mXVcCgYBnhdnzXmve25+UxhXYbyLIojS4NBNWlgjZ+/2u" +
            "BdfP0phJ2y5SLPe40YQlD8HTppQ3lKMavyK4eq+RKvm04QLW04PHOUyvDYMfymhI" +
            "+t+K+13kFCWKSh9WY+xkcn551G0C3mbo5okGNgT7YITUpFJIPsaSK8k3E/2/5y2X" +
            "FZyd6QKBgBbey6fwR25zq8lTKC0rIDZ/8bfANhS7+CC6z8D9Che5sIekv8RhlLwh" +
            "ilBvcrs/XrwGGETUcFYcnYI7I0YwJKeL2V/5AGcAjPR5TeFdIUKbyj0QdYdDnNcc" +
            "IIlb1qLenrvtSfLJTsnmPR3uB0yRIJ/aPn+IlpQq4zjPG7//4Zs0";

    private Crypto mCrypto;
    private Identity mIdentity;
    
    @Before
    public void setUp() throws Exception {
        mCrypto = Util.getCryptoInstance();
        mIdentity = new Identity(
                mCrypto.createRSAKeyPair(
                        mCrypto.decodeRSAPublicKey(
                                Util.base64Decode(IDENTITY_PUBLIC_KEY)
                        ),
                        mCrypto.decodeRSAPrivateKey(
                                Util.base64Decode(IDENTITY_PRIVATE_KEY)
                        )
                )
        );
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
    public void testGenerateIdentity() throws Exception {
        Identity identity = mCrypto.generateIdentity();
        byte[] hashName = identity.getHashName();
        assertNotNull(hashName);
        assertTrue(hashName.length == 32);
    }

    @Test
    public void testRSAPublicKeyEncodeDecode() throws Exception {
        // DER-encode the public key
        RSAPublicKey publicKey = mIdentity.getPublicKey();
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
        // DER-encode the private key
        RSAPrivateKey privateKey = mIdentity.getPrivateKey();
        byte[] privateKeyBytes = privateKey.getDEREncoded();
        String privateKeyHex = Util.bytesToHex(privateKeyBytes);

        // DER-decode the private key
        byte[] privateKeyBytes2 = Util.hexToBytes(privateKeyHex);
        assertEquals(privateKeyHex, Util.bytesToHex(privateKeyBytes2));
        RSAPrivateKey privateKey2 = mCrypto.decodeRSAPrivateKey(privateKeyBytes2);
        assertEquals(privateKeyHex, Util.bytesToHex(privateKey2.getDEREncoded()));
    }
    
    @Test
    public void testRSAPublicKeyReadWrite() throws Exception {
        File publicKeyFile = File.createTempFile("test-public", ".pub");
        String publicKeyFilename = publicKeyFile.getAbsolutePath();
        File privateKeyFile = File.createTempFile("test-private", ".key");
        String privateKeyFilename = privateKeyFile.getAbsolutePath();
        
        // write to files
        mCrypto.writeRSAPublicKeyToFile(publicKeyFilename, mIdentity.getPublicKey());
        mCrypto.writeRSAPrivateKeyToFile(privateKeyFilename, mIdentity.getPrivateKey());
        
        // read from files
        RSAPublicKey readPublicKey = mCrypto.readRSAPublicKeyFromFile(publicKeyFilename);
        RSAPrivateKey readPrivateKey = mCrypto.readRSAPrivateKeyFromFile(privateKeyFilename);
        
        // assert equality
        assertArrayEquals(mIdentity.getPublicKey().getDEREncoded(), readPublicKey.getDEREncoded());
        assertArrayEquals(mIdentity.getPrivateKey().getDEREncoded(), readPrivateKey.getDEREncoded());
        
        // clean up
        publicKeyFile.delete();
        privateKeyFile.delete();
    }
    
    @Test
    public void testRSAEncryptDecrypt() throws Exception {
        // cycle keys through an encode/decode cycle to validate that
        // those methods aren't losing information necessary for the
        // encryption/decryption.  (The test*EncodeDecode() methods
        // above only verify consistency, not correctness.)
        RSAPublicKey publicKey = mCrypto.decodeRSAPublicKey(
                Util.hexToBytes(
                        Util.bytesToHex(
                                mIdentity.getPublicKey().getDEREncoded()
                        )
                )
        );
        RSAPrivateKey privateKey = mCrypto.decodeRSAPrivateKey(
                Util.hexToBytes(
                        Util.bytesToHex(
                                mIdentity.getPrivateKey().getDEREncoded()
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
    
    private static final String EXPECTED_SIGNATURE =
            "eapjm0CIenRMV+3f+tBYmCgsBGUEnlijb03idHeCQgbQ4TWxIAdXMSOXGNN9ikuZ" +
            "bpNyGDKO+vnRMNvtw7gLO+Mtgj3hUD5uoRg1NDYL1JK4VhAkbsysjh8wX8T14dav" +
            "BSxs62o2MjucXAt8ZWjNvFUtJzihrHFc8z1D9Vf48Tt5/oIYHNEGiLxrQle1f7Uf" +
            "bHWVMdNsjEIEWEvVNFBvXkL7G9kyUBIybk/Z6SmPBlk+lc0GSlPj/jQ+YuIwFXQs" +
            "uCP1vnoxbYgmLQEuNX+wnTK4BiXHAUGQCfQNdEnDx3O6jWegNl33Ws395BcO/Auo" +
            "pA8GPZ1GwwaTDsC4838vWA==";
    
    @Test
    public void testRSASigning() throws Exception {
        byte[] signature = mCrypto.signRSA(
                mIdentity.getPrivateKey(),
                TEST_MESSAGE.getBytes("UTF-8")
        );
        assertNotNull(signature);
        byte[] expectedSignature = Util.base64Decode(EXPECTED_SIGNATURE);
        assertTrue(expectedSignature.length == signature.length);
        assertArrayEquals(expectedSignature, signature);
    }
    
    @Test
    public void testECPublicKeyEncodeDecode() throws Exception {
        ECKeyPair keyPair = mCrypto.generateECKeyPair();
        
        // DER-encode the public key
        ECPublicKey publicKey = keyPair.getPublicKey();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String publicKeyHex = Util.bytesToHex(publicKeyBytes);
        
        // DER-decode the public key
        byte[] publicKeyBytes2 = Util.hexToBytes(publicKeyHex);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKeyBytes2));
        ECPublicKey publicKey2 = mCrypto.decodeECPublicKey(publicKeyBytes2);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKey2.getEncoded()));
    }
    
    /*
    @Test
    public void testECPrivateKeyEncodeDecode() throws Exception {
        ECKeyPair keyPair = mCrypto.generateECKeyPair();
        
        // DER-encode the public key
        ECPrivateKey privateKey = keyPair.getPrivateKey();
        byte[] privateKeyBytes = privateKey.getEncoded();
        String privateKeyHex = Util.bytesToHex(privateKeyBytes);
        
        // DER-decode the public key
        byte[] privateKeyBytes2 = Util.hexToBytes(privateKeyHex);
        assertEquals(privateKeyHex, Util.bytesToHex(privateKeyBytes2));
        ECPrivateKey privateKey2 = mCrypto.decodeECPrivateKey(privateKeyBytes2);
        assertEquals(privateKeyHex, Util.bytesToHex(privateKey2.getEncoded()));
    }
    */
    
    @Test
    public void testECDHKeyAgreement() throws Exception {
        ECKeyPair localKeyPair = mCrypto.generateECKeyPair();
        ECKeyPair remoteKeyPair = mCrypto.generateECKeyPair();
        
        // cycle the remote end's received version of the local public
        // key through an encode/decode cycle to validate that
        // those methods aren't losing information necessary for
        // ECDH.  (The test*EncodeDecode() methods above only verify
        // consistency, not correctness.)
        ECPublicKey localPublicKeyAsReceivedByRemote =
                mCrypto.decodeECPublicKey(
                        Util.hexToBytes(
                                Util.bytesToHex(
                                        localKeyPair.getPublicKey().getEncoded()
                                )
                        )
                );

        byte[] localSharedSecret = mCrypto.calculateECDHSharedSecret(
                remoteKeyPair.getPublicKey(),
                localKeyPair.getPrivateKey()
        );
        byte[] remoteSharedSecret = mCrypto.calculateECDHSharedSecret(
                localPublicKeyAsReceivedByRemote,
                remoteKeyPair.getPrivateKey()
        );
        assertArrayEquals(localSharedSecret, remoteSharedSecret);
    }
    
    @Test
    public void testAES() throws Exception {
        byte[] plaintext = mCrypto.sha256Digest("hello".getBytes("UTF-8"));
        byte[] key = mCrypto.sha256Digest("secret".getBytes("UTF-8"));
        byte[] iv = {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };

        byte[] ciphertext;
        ciphertext = mCrypto.encryptAES256CTR(plaintext, iv, key);
        byte[] decryptedPlainText;
        decryptedPlainText = mCrypto.decryptAES256CTR(ciphertext, iv, key);

        assertArrayEquals(plaintext, decryptedPlainText);
    }
}
