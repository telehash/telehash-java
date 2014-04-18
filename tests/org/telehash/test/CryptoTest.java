/**
 *
 */
package org.telehash.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.HashName;
import org.telehash.core.LocalNode;
import org.telehash.core.Util;
import org.telehash.crypto.CipherSet;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.crypto.LineKeyPair;
import org.telehash.crypto.LinePublicKey;
import org.telehash.crypto.impl.CryptoImpl;

import java.io.File;
import java.util.SortedMap;
import java.util.TreeMap;

public class CryptoTest {

    private static final String TEST_MESSAGE = "This is a test.";
    private static final String TEST_MESSAGE_DIGEST =
            "a8a2f6ebe286697c527eb35a58b5539532e9b3ae3b64d4eb0a46fb657b41562c";

    private static final CipherSetIdentifier CIPHER_SET_ID = new CipherSetIdentifier(0x2a);

    private static final String LOCALNODE_PUBLIC_KEY =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvv8h0XuJHXaUaQpBDFTA" +
            "e6Pj2evamzkTgA2QfYcMjcmRK4V+o7Kv54RvD02MQIGJGSEF2nsqKcE4MpseRWGB" +
            "PH3/mILG+ru30IxjKscIPwADHll8DOTkfez24XP5CvqNeXkoKV9/AgtYkrII4Kh/" +
            "P9qxREs/aPuov2JSlZAspznaj45SVodeStRzb1rQPM672AqednZ2PzD/WQFaLy/y" +
            "nBuEcKSeGSpyFyzXJF4sz8kietALRnoKjkAGNTyrrteYLRiPRa0ek/1kq7tZ6168" +
            "dhOxRQD4vZwh6wZm35eV1XlbllchvgtgCt10lXsSZhSKsb6/4TW2KlZtb8IaHCqt" +
            "lwIDAQAB";
    private static final String LOCALNODE_PRIVATE_KEY =
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

    private static final byte[] AES_PLAINTEXT = Util.base64Decode(
            "AIZ7ImF0IjoxMzg1NTgxNTIxMTYxLCJ0byI6IjMzYmIwZDVhOTFkZmIzMzlkZjU1"+
            "MzkyMTRhYThlODYzNTk5NjEzMTE0MTQ4OWU1Y2FmZTllYjg5ZTRjOTEyMDAiLCJs"+
            "aW5lIjoiODVlYjVjY2IwODc4YmFmZDVlMTYyMzg4M2E5MWNmNGYifTCCASIwDQYJ"+
            "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAL8R/ZUlJHfvsDAYsx9TrSVH9jE+l6Uh"+
            "9lVXO97GFoXrSDXJC+MYbaM1mNlVH0qz7dGtA4GbcloVYdU5c4cuKZd9TmJU7/x9"+
            "AS7Sndh60rCVGUjXl/JKeCgtLIlPfAJ2YrQOJorAb5yfrP8V0mbFnQgGwj8cJA4F"+
            "rfXIEF+IoiqNw1ef/etJvDeK33lYjI29uJ2vLpyREQ1Z9WHBKLLBwq5eGtASTsap"+
            "EBJa4lJXq9EsBIDv/+SsVOuiy8R5lwMtrQOt9I+nu1yx0nzllcIr6JhkinyO5OHR"+
            "tUs5wV5d7GvSG6uul0bZba2rbZ/plurENhgdA4oIA3hKCwqoc9SAowsCAwEAAQ=="
    );
    private static final byte[] AES_IV = Util.hexToBytes("a95b836b9c12c3ce35e166218237596b");
    private static final byte[] AES_KEY =
            Util.hexToBytes("585501ae7f7de80ea07ecf09a1d78b2962d2fd98a6644a0c1b9dd58e57139e0c");
    private static final byte[] EXPECTED_AES_CIPHERTEXT = Util.base64Decode(
            "T7eXkxL/rvT4twHFL3X+Jhi+9Q1clDWepIpp87afv7o55ydRx29F1O9ngMDGciXa"+
            "95exGhK2moMQgiCdooznL8/wpWL6feFle4OZH1q8qvvaeuAUYav8+ETDmw/gMUD6"+
            "iOghLpsSgUEhLgbejIaN68RWVW/MQraCPUMHweV8QvCebfeofXGQnyY8hknZ54u+"+
            "iqLZCS0uy9hW8Z2dPOijJ7eyxEJGBM7k4gk6SfOdjLFRWTVpmAL76S/h80m6x3ZK"+
            "D1z4EqmHh672pZXJ5Je9eviEHihRJFsK0ch8xwM9iQrV8BRYltl00a9l1TbNlW/q"+
            "W9IyoclN9r5J0kqHLWe6qbuWCVu1yCnfFY9aq4P7MCjEHpzYTQMmkgt0rNiq2Ce9"+
            "3VOugk3QOMwI7DmlH5j0QeKm9LNriz0dfHlSx4ahAwdHYSlQA5k/JlUQ+ctMDL8+"+
            "PK1ixqTz+b/4DGfhCMoePIRC38BHtflgqm6It0aeLhn9cp7W5GaKEhV/93W0fJfq"+
            "4bf9Yew3UWhbVTiTmR66m0j891b/ohvJKvdLzUHTQesMtf9q5rO8VKJ1S8AwGw=="
    );

    private Crypto mCrypto;
    private CipherSet mCipherSet;
    private LocalNode mLocalNode;

    @Before
    public void setUp() throws Exception {
        mCrypto = new CryptoImpl();
        mCipherSet = mCrypto.getCipherSet(CIPHER_SET_ID);
        HashNameKeyPair keyPair = mCipherSet.createHashNameKeyPair(
                mCipherSet.decodeHashNamePublicKey(Util.base64Decode(LOCALNODE_PUBLIC_KEY)),
                mCipherSet.decodeHashNamePrivateKey(Util.base64Decode(LOCALNODE_PRIVATE_KEY))
        );
        SortedMap<CipherSetIdentifier,HashNameKeyPair> keyPairMap =
                new TreeMap<CipherSetIdentifier,HashNameKeyPair>();
        keyPairMap.put(CIPHER_SET_ID, keyPair);
        mLocalNode = new LocalNode(keyPairMap);
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
    public void testGenerateLocalNode() throws Exception {
        LocalNode localNode = mCrypto.generateLocalNode();
        HashName hashName = localNode.getHashName();
        assertNotNull(hashName);
        byte[] hashNameBytes = hashName.getBytes();
        assertNotNull(hashNameBytes);
        assertTrue(hashNameBytes.length == 32);
    }

    @Test
    public void testRSAPublicKeyEncodeDecode() throws Exception {
        // DER-encode the public key
        HashNamePublicKey publicKey = mLocalNode.getPublicKey(CIPHER_SET_ID);
        byte[] publicKeyBytes = publicKey.getEncoded();
        String publicKeyHex = Util.bytesToHex(publicKeyBytes);

        // DER-decode the public key
        byte[] publicKeyBytes2 = Util.hexToBytes(publicKeyHex);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKeyBytes2));
        HashNamePublicKey publicKey2 = mCipherSet.decodeHashNamePublicKey(publicKeyBytes2);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKey2.getEncoded()));
    }

    @Test
    public void testRSAPrivateKeyEncodeDecode() throws Exception {
        // DER-encode the private key
        HashNamePrivateKey privateKey = mLocalNode.getPrivateKey(CIPHER_SET_ID);
        byte[] privateKeyBytes = privateKey.getEncoded();
        String privateKeyHex = Util.bytesToHex(privateKeyBytes);

        // DER-decode the private key
        byte[] privateKeyBytes2 = Util.hexToBytes(privateKeyHex);
        assertEquals(privateKeyHex, Util.bytesToHex(privateKeyBytes2));
        HashNamePrivateKey privateKey2 = mCipherSet.decodeHashNamePrivateKey(privateKeyBytes2);
        assertEquals(privateKeyHex, Util.bytesToHex(privateKey2.getEncoded()));
    }

    @Test
    public void testRSAPublicKeyReadWrite() throws Exception {
        File publicKeyFile = File.createTempFile("test-public", ".pub");
        String publicKeyFilename = publicKeyFile.getAbsolutePath();
        File privateKeyFile = File.createTempFile("test-private", ".key");
        String privateKeyFilename = privateKeyFile.getAbsolutePath();

        // write to files
        mCipherSet.writeHashNamePublicKeyToFile(
                publicKeyFilename,
                mLocalNode.getPublicKey(CIPHER_SET_ID)
        );
        mCipherSet.writeHashNamePrivateKeyToFile(
                privateKeyFilename,
                mLocalNode.getPrivateKey(CIPHER_SET_ID)
        );

        // read from files
        HashNamePublicKey readPublicKey =
                mCipherSet.readHashNamePublicKeyFromFile(publicKeyFilename);
        HashNamePrivateKey readPrivateKey =
                mCipherSet.readHashNamePrivateKeyFromFile(privateKeyFilename);

        // assert equality
        assertArrayEquals(
                mLocalNode.getPublicKey(CIPHER_SET_ID).getEncoded(),
                readPublicKey.getEncoded()
        );
        assertArrayEquals(
                mLocalNode.getPrivateKey(CIPHER_SET_ID).getEncoded(),
                readPrivateKey.getEncoded()
        );

        // clean up
        publicKeyFile.delete();
        privateKeyFile.delete();
    }

    @Test
    public void testRSAEncryptDecryptOAEP() throws Exception {
        // cycle keys through an encode/decode cycle to validate that
        // those methods aren't losing information necessary for the
        // encryption/decryption.  (The test*EncodeDecode() methods
        // above only verify consistency, not correctness.)
        HashNamePublicKey publicKey = mCipherSet.decodeHashNamePublicKey(
                Util.hexToBytes(
                        Util.bytesToHex(
                                mLocalNode.getPublicKey(CIPHER_SET_ID).getEncoded()
                        )
                )
        );
        HashNamePrivateKey privateKey = mCipherSet.decodeHashNamePrivateKey(
                Util.hexToBytes(
                        Util.bytesToHex(
                                mLocalNode.getPrivateKey(CIPHER_SET_ID).getEncoded()
                        )
                )
        );

        // encrypt
        byte[] cipherText = mCrypto.encryptRSAOAEP(publicKey, TEST_MESSAGE.getBytes("UTF-8"));
        // decrypt
        byte[] clearText = mCrypto.decryptRSAOAEP(privateKey, cipherText);
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
                mLocalNode.getPrivateKey(CIPHER_SET_ID),
                TEST_MESSAGE.getBytes("UTF-8")
        );
        assertNotNull(signature);
        byte[] expectedSignature = Util.base64Decode(EXPECTED_SIGNATURE);
        assertTrue(expectedSignature.length == signature.length);
        assertArrayEquals(expectedSignature, signature);
    }

    private static final byte[] RSA_PUBLIC_KEY = Util.base64Decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxH9lSUkd++wMBizH1Ot"+
            "JUf2MT6XpSH2VVc73sYWhetINckL4xhtozWY2VUfSrPt0a0DgZtyWhVh1Tlzhy4p"+
            "l31OYlTv/H0BLtKd2HrSsJUZSNeX8kp4KC0siU98AnZitA4misBvnJ+s/xXSZsWd"+
            "CAbCPxwkDgWt9cgQX4iiKo3DV5/960m8N4rfeViMjb24na8unJERDVn1YcEossHC"+
            "rl4a0BJOxqkQElriUler0SwEgO//5KxU66LLxHmXAy2tA630j6e7XLHSfOWVwivo"+
            "mGSKfI7k4dG1SznBXl3sa9Ibq66XRtltrattn+mW6sQ2GB0DiggDeEoLCqhz1ICj"+
            "CwIDAQAB"
    );

    private static final byte[] RSA_PRIVATE_KEY = Util.base64Decode(
            "MIIEpQIBAAKCAQEAvxH9lSUkd++wMBizH1OtJUf2MT6XpSH2VVc73sYWhetINckL"+
            "4xhtozWY2VUfSrPt0a0DgZtyWhVh1Tlzhy4pl31OYlTv/H0BLtKd2HrSsJUZSNeX"+
            "8kp4KC0siU98AnZitA4misBvnJ+s/xXSZsWdCAbCPxwkDgWt9cgQX4iiKo3DV5/9"+
            "60m8N4rfeViMjb24na8unJERDVn1YcEossHCrl4a0BJOxqkQElriUler0SwEgO//"+
            "5KxU66LLxHmXAy2tA630j6e7XLHSfOWVwivomGSKfI7k4dG1SznBXl3sa9Ibq66X"+
            "Rtltrattn+mW6sQ2GB0DiggDeEoLCqhz1ICjCwIDAQABAoIBAQC2zhGd1nFzxoD9"+
            "I0SNHlO0LYtgRhB0T3AM6m8/jqoR6q+ltfqHheGvmyHoHUbZBBju2OdX40+e3IJD"+
            "rLnZhdMJOzv5XGZXXYn6MEwQyEI37A7K4Gphx9n6Jm5L2R4+hOGef0Nk0QR4B1VO"+
            "oKQy67J38W97TgM43zo2wvjXTjRJHLuD+SHv38AZy9b16DQOzVw7ak89KHXS/KHT"+
            "4bfLHvhsI5MxR2liEui8LLRtODO/7FyZIUiFT3JNCorg3EYadKomxA4YaO7hxTcW"+
            "qo58DsTP3WeoV2aOxuIeO1yj6UVlIYDI8xs9ZeiZmpuuXypzlfqVrigmy+lJ7dmJ"+
            "ilMkbKNRAoGBAPSdmIGRFs4CCxpDaQrUzGUqZ2EkoFtkBpwaKI8wEamCSghkhqyO"+
            "oKddde5Nb/NgnwOGHyc7aNJM/RGnuk2AqY2ie+UYS44jsa105wwNMOuQk3yqqTTH"+
            "MUzv5j0o90wvK+zD/AjK/jcseSYu082UvtQ6Xm6AOKpH4/2d9NwGHOC/AoGBAMf2"+
            "caWuuwj0BPLGm+x3ovLAAJiIdeUU1QYBM8WkZotdGs+yB0ySaJrQhVkJRWzPLGT2"+
            "J1quBCelCaAZXr/XxSSRMTD78vMIGsC7yT6Uslf1zWoApBka11eawkE+0wkOo/RQ"+
            "oljZm/AHf9jb66PxUBShC+UU9sNwy9B+ziUPXUS1AoGAQz+EKrKZg18acEjx+tFP"+
            "s8w5iYJJN3bDPm0Ok3bSlDhGZBJG1++KCRjvj+joCw+YB576t41kntQdipoC5MWn"+
            "V1HBH9VTCCuV8CrAThbeSRSBB3ffdqwASLd3I388pUwelkO26S/tPXvTfoTHI7Bt"+
            "2eiGB3jmmyGScynWpBpmG/8CgYEAr4kE7Pf9Une8HE8DM8s2LTkljMFGFUp7UmEd"+
            "zKNsLW0XCzpyM+LWlwjz9lwwKLuZciuwEmduWEsFrxh2V5yXgGlAsIqMFJKJwaVX"+
            "nWs1QAgUQbi8VRl97nZ5joMTCQFkJiXeznaA8G306i7spadBsEpLwdbsZFcRZD7c"+
            "wiXBr30CgYEAnMYg1M0alFbtLJQN+B+xNCKf+49b6fOwLvkt1XnkFOMEWDnaHyst"+
            "TSkuDEy1LQU99Iw0xIdTj38VQEpYbPTM3DqdAQDnQ4a0j1NidRrzZGHDGZie90pi"+
            "d66vFcnmRXGncwTdoHInpdJAnYVfrcT6Nv2RUPWk55t4p8/4FevvO+s="
    );
    private static final byte[] MESSAGE_TO_SIGN = Util.base64Decode(
            "T7eXkxL/rvT4twHFL3X+Jhi+9Q1clDWepIpp87afv7o55ydRx29F1O9ngMDGciXa"+
            "95exGhK2moMQgiCdooznL8/wpWL6feFle4OZH1q8qvvaeuAUYav8+ETDmw/gMUD6"+
            "iOghLpsSgUEhLgbejIaN68RWVW/MQraCPUMHweV8QvCebfeofXGQnyY8hknZ54u+"+
            "iqLZCS0uy9hW8Z2dPOijJ7eyxEJGBM7k4gk6SfOdjLFRWTVpmAL76S/h80m6x3ZK"+
            "D1z4EqmHh672pZXJ5Je9eviEHihRJFsK0ch8xwM9iQrV8BRYltl00a9l1TbNlW/q"+
            "W9IyoclN9r5J0kqHLWe6qbuWCVu1yCnfFY9aq4P7MCjEHpzYTQMmkgt0rNiq2Ce9"+
            "3VOugk3QOMwI7DmlH5j0QeKm9LNriz0dfHlSx4ahAwdHYSlQA5k/JlUQ+ctMDL8+"+
            "PK1ixqTz+b/4DGfhCMoePIRC38BHtflgqm6It0aeLhn9cp7W5GaKEhV/93W0fJfq"+
            "4bf9Yew3UWhbVTiTmR66m0j891b/ohvJKvdLzUHTQesMtf9q5rO8VKJ1S8AwGw=="
    );
    private static final byte[] EXPECTED_SIGNATURE_2 = Util.base64Decode(
            "jR7saWz/vK90vv/sJcDuqPtZxFfFMjeFnGfHWz/LsnKPzyICiOrR9dJsHYCUWCyE"+
            "4YIMNEdAK0lYvAb5ttpUjY1f3FgkV9YewNKpYssgnj36m1Bn/gWhkLo6obNpMQlM"+
            "q2ZzOdZJ3+Q0vQeANgkEMrOnZHyfv0s3fHob0VU0X/SIiqC0OSPuSwbiTh2d8Yr+"+
            "AjS4et/fN+7UhFHYzIGNZrIUmRpJ4ULS7JijBErPMJSLawBaKe9fQPR0MCofMzQQ"+
            "E3uXX3ygYYrH/IETpi9IZUL1bl+gLH/XVQ+hAbKZq784wggwxc8Wy9COFHrtzrt4"+
            "V6xJiNrnw9j0IojtpMvXAw=="
    );

    @Test
    public void testRSASigning2() throws Exception {
        byte[] signature = mCrypto.signRSA(
                mCipherSet.decodeHashNamePrivateKey(RSA_PRIVATE_KEY),
                MESSAGE_TO_SIGN
        );

        assertNotNull(signature);
        assertTrue(EXPECTED_SIGNATURE_2.length == signature.length);
        assertArrayEquals(EXPECTED_SIGNATURE_2, signature);

        boolean verify = mCrypto.verifyRSA(
                mCipherSet.decodeHashNamePublicKey(RSA_PUBLIC_KEY),
                MESSAGE_TO_SIGN,
                signature
        );
        assertTrue(verify);
    }

    @Test
    public void testECPublicKeyEncodeDecode() throws Exception {
        LineKeyPair keyPair = mCipherSet.generateLineKeyPair();

        // DER-encode the public key
        LinePublicKey publicKey = keyPair.getPublicKey();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String publicKeyHex = Util.bytesToHex(publicKeyBytes);

        // DER-decode the public key
        byte[] publicKeyBytes2 = Util.hexToBytes(publicKeyHex);
        assertEquals(publicKeyHex, Util.bytesToHex(publicKeyBytes2));
        LinePublicKey publicKey2 = mCipherSet.decodeLinePublicKey(publicKeyBytes2);
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
        LineKeyPair localKeyPair = mCipherSet.generateLineKeyPair();
        LineKeyPair remoteKeyPair = mCipherSet.generateLineKeyPair();

        // cycle the remote end's received version of the local public
        // key through an encode/decode cycle to validate that
        // those methods aren't losing information necessary for
        // ECDH.  (The test*EncodeDecode() methods above only verify
        // consistency, not correctness.)
        LinePublicKey localPublicKeyAsReceivedByRemote =
                mCipherSet.decodeLinePublicKey(
                        Util.hexToBytes(
                                Util.bytesToHex(
                                        localKeyPair.getPublicKey().getEncoded()
                                )
                        )
                );

        byte[] localSharedSecret = mCipherSet.calculateECDHSharedSecret(
                remoteKeyPair.getPublicKey(),
                localKeyPair.getPrivateKey()
        );
        byte[] remoteSharedSecret = mCipherSet.calculateECDHSharedSecret(
                localPublicKeyAsReceivedByRemote,
                remoteKeyPair.getPrivateKey()
        );
        assertArrayEquals(localSharedSecret, remoteSharedSecret);
    }

    /*
    @Test
    public void testAESSimple() throws Exception {
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

    @Test
    public void testAESEncrypt() throws Exception {
        byte[] cipherText = mCrypto.encryptAES256CTR(AES_PLAINTEXT, AES_IV, AES_KEY);
        assertArrayEquals(EXPECTED_AES_CIPHERTEXT, cipherText);
    }
    */

}
