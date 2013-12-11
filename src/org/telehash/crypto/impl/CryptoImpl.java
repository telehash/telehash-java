package org.telehash.crypto.impl;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.telehash.core.Identity;
import org.telehash.core.TelehashException;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.ECKeyPair;
import org.telehash.crypto.ECPrivateKey;
import org.telehash.crypto.ECPublicKey;
import org.telehash.crypto.RSAKeyPair;
import org.telehash.crypto.RSAPrivateKey;
import org.telehash.crypto.RSAPublicKey;

/**
 * This class contains implementations for the basic cryptographic functions
 * needed by Telehash.
 */
public class CryptoImpl implements Crypto {
    
    private static final String RSA_PRIVATE_KEY_PEM_TYPE = "RSA PRIVATE KEY";
    private static final String RSA_PUBLIC_KEY_PEM_TYPE = "PUBLIC KEY";
    
    private SecureRandom random = new SecureRandom();

    // elliptic curve settings
    private ECNamedCurveParameterSpec mECNamedCurveParameterSpec;
    private ECKeyPairGenerator mECGenerator = new ECKeyPairGenerator();
    private ECDomainParameters mECDomainParameters;
    private ECKeyGenerationParameters mECKeyGenerationParameters;

    static {
        Security.addProvider(new BouncyCastleProvider());
    };    
    
    public CryptoImpl() {
        // initialize elliptic curve parameters and generator
        mECNamedCurveParameterSpec =
                ECNamedCurveTable.getParameterSpec("prime256v1");
        mECGenerator = new ECKeyPairGenerator();
        mECDomainParameters =
                new ECDomainParameters(
                        mECNamedCurveParameterSpec.getCurve(),
                        mECNamedCurveParameterSpec.getG(),
                        mECNamedCurveParameterSpec.getN()
                );
        mECKeyGenerationParameters =
                new ECKeyGenerationParameters(mECDomainParameters, random);        
        mECGenerator.init(mECKeyGenerationParameters);
    }

    /**
     * Generate a cryptographically secure pseudo-random array of byte values.
     * 
     * @param size The number of random bytes to produce.
     * @return The array of random byte values.
     */
    @Override
    public byte[] getRandomBytes(int size) {
        
        // TODO
        // We create a SecureRandom object once, so it's seeded only once.
        // The following page actual recommends forcing the PRNG to re-seed
        // periodically, but doesn't indicate what interval might be best:
        // https://www.cigital.com/justice-league-blog/2009/08/14/proper-use-of-javas-securerandom/
        // What should the best practice be?
        
        // TODO
        // The Android SecureRandom PRNG is faulty. :(
        // Recommended fix for the Android case:
        // http://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html
        
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Return a SHA-256 digest of the provided byte buffer.
     * 
     * @param buffer The buffer to digest.
     * @return A 32-byte array representing the digest.
     */
    @Override
    public byte[] sha256Digest(byte[] buffer) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(buffer, 0, buffer.length);
        byte[] output = new byte[256/8];
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * Generate a fresh identity (i.e., RSA public and private key pair) for a
     * newly provisioned Telehash node.
     * 
     * @return The new identity.
     * @throws TelehashException 
     */
    @Override
    public Identity generateIdentity() throws TelehashException {
        // generate a 2048 bit key pair
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(
                new RSAKeyGenerationParameters(
                    new BigInteger("10001", 16),//publicExponent
                    // TODO: see warning in getRandomBytes()!
                    new SecureRandom(),
                    2048, // key length
                    80    // prime certainty
                )
            );
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        
        AsymmetricKeyParameter publicKey = keyPair.getPublic();
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        if (! (privateKey instanceof RSAPrivateCrtKeyParameters)) {
            throw new TelehashException("generated key is not an RSA private key.");
        }
        return new Identity(
                new RSAKeyPairImpl(
                        new RSAPublicKeyImpl(publicKey),
                        new RSAPrivateKeyImpl((RSAPrivateCrtKeyParameters)privateKey)
                )
        );
    }

    /**
     * Generate a fresh elliptic curve key pair
     */
    @Override
    public ECKeyPair generateECKeyPair() throws TelehashException {
        AsymmetricCipherKeyPair keyPair = mECGenerator.generateKeyPair();
        
        AsymmetricKeyParameter publicKey = keyPair.getPublic();
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        if (! (publicKey instanceof ECPublicKeyParameters)) {
            throw new TelehashException("generated key is not an elliptic curve public key.");
        }
        if (! (privateKey instanceof ECPrivateKeyParameters)) {
            throw new TelehashException("generated key is not an elliptic curve private key.");
        }
        return new ECKeyPairImpl(
                (ECPublicKeyParameters)publicKey,
                (ECPrivateKeyParameters)privateKey
        );
    }
    
    /**
     * Encrypt data with an RSA private key
     * @throws TelehashException 
     */
    @Override
    public byte[] encryptRSA(RSAPublicKey key, byte[] clearText) throws TelehashException {
        AsymmetricBlockCipher cipher = new RSAEngine();
        cipher.init(true, ((RSAPublicKeyImpl)key).getKey());
        byte[] cipherText;
        try {
            cipherText = cipher.processBlock(clearText, 0, clearText.length);
        } catch (InvalidCipherTextException e) {
            throw new TelehashException(e);
        }
        return cipherText;
    }
    
    /**
     * Encrypt data with an RSA private key using OAEP padding
     * @throws TelehashException 
     */
    @Override
    public byte[] encryptRSAOAEP(RSAPublicKey key, byte[] clearText) throws TelehashException {
        AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        cipher.init(true, ((RSAPublicKeyImpl)key).getKey());
        byte[] cipherText;
        try {
            cipherText = cipher.processBlock(clearText, 0, clearText.length);
        } catch (InvalidCipherTextException e) {
            throw new TelehashException(e);
        }
        return cipherText;
    }

    /**
     * Decrypt data with an RSA private key
     * @throws TelehashException 
     */
    @Override
    public byte[] decryptRSA(RSAPrivateKey key, byte[] cipherText) throws TelehashException {
        AsymmetricBlockCipher cipher = new RSAEngine();
        cipher.init(false, ((RSAPrivateKeyImpl)key).getKey());
        byte[] clearText;
        try {
            clearText = cipher.processBlock(cipherText, 0, cipherText.length);
        } catch (InvalidCipherTextException e) {
            throw new TelehashException(e);
        }
        return clearText;
    }

    /**
     * Decrypt data with an RSA private key and OAEP padding
     * @throws TelehashException 
     */
    @Override
    public byte[] decryptRSAOAEP(RSAPrivateKey key, byte[] cipherText) throws TelehashException {
        AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        cipher.init(false, ((RSAPrivateKeyImpl)key).getKey());
        byte[] clearText;
        try {
            clearText = cipher.processBlock(cipherText, 0, cipherText.length);
        } catch (InvalidCipherTextException e) {
            throw new TelehashException(e);
        }
        return clearText;
    }

    /**
     * Sign a data buffer with an RSA private key using the SHA-256 digest, and
     * PKCSv1.5 padding.
     * 
     * @throws TelehashException 
     */
    @Override
    public byte[] signRSA(RSAPrivateKey key, byte[] buffer) throws TelehashException {
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(true, ((RSAPrivateKeyImpl)key).getKey());
        signer.update(buffer, 0, buffer.length);
        byte[] signature;
        try {
            signature = signer.generateSignature();
        } catch (DataLengthException e) {
            throw new TelehashException(e);
        } catch (CryptoException e) {
            throw new TelehashException(e);
        }
        return signature;
    }

    /**
     * Verify the signature of a data buffer with an RSA private key using the
     * SHA-256 digest, and PKCSv1.5 padding.
     *
     * @param key The RSA public key
     * @param buffer The buffer which was signed
     * @param signature The signature to verify
     * @return true if the signature is valid; false otherwise.
     * @throws TelehashException
     */
    @Override
    public boolean verifyRSA(
            RSAPublicKey key,
            byte[] buffer,
            byte[] signature
    ) throws TelehashException {
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(false, ((RSAPublicKeyImpl)key).getKey());
        signer.update(buffer, 0, buffer.length);
        try {
            return signer.verifySignature(signature);
        } catch (DataLengthException e) {
            throw new TelehashException(e);
        }
    }
    
    /**
     * Parse a PEM-formatted RSA public key
     * 
     * @param pem The PEM string.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    @Override
    public RSAPublicKey parseRSAPublicKeyFromPEM(String pem) throws TelehashException {
        try {
            PemReader pemReader = new PemReader(new StringReader(pem));
            PemObject pemObject = pemReader.readPemObject();
            pemReader.close();
            if (pemObject == null) {
                throw new TelehashException("cannot parse RSA public key PEM file.");
            }
            if (! pemObject.getType().equals(RSA_PUBLIC_KEY_PEM_TYPE)) {
                throw new TelehashException(
                        "RSA public key PEM file of incorrect type \"" +
                        pemObject.getType() + "\""
                );
            }
            return new RSAPublicKeyImpl(PublicKeyFactory.createKey(pemObject.getContent()));
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Read a PEM-formatted RSA public key from a file.
     * 
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    @Override
    public RSAPublicKey readRSAPublicKeyFromFile(String filename) throws TelehashException {
        try {
            PemReader pemReader = new PemReader(new FileReader(filename));
            PemObject pemObject = pemReader.readPemObject();
            pemReader.close();
            if (pemObject == null) {
                throw new TelehashException("cannot parse RSA public key PEM file.");
            }
            if (! pemObject.getType().equals(RSA_PUBLIC_KEY_PEM_TYPE)) {
                throw new TelehashException(
                        "RSA public key PEM file of incorrect type \"" +
                        pemObject.getType() + "\""
                );
            }
            return new RSAPublicKeyImpl(PublicKeyFactory.createKey(pemObject.getContent()));
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }
        
    /**
     * Read a PEM-formatted RSA private key from a file.
     * 
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    @Override
    public RSAPrivateKey readRSAPrivateKeyFromFile(String filename) throws TelehashException {
        try {
            PemReader pemReader = new PemReader(new FileReader(filename));
            PemObject pemObject = pemReader.readPemObject();
            pemReader.close();
            if (pemObject == null) {
                throw new TelehashException("cannot parse RSA private key PEM file.");
            }
            if (! pemObject.getType().equals(RSA_PRIVATE_KEY_PEM_TYPE)) {
                throw new TelehashException(
                        "RSA private key PEM file of incorrect type \"" +
                        pemObject.getType() + "\""
                );
            }
            return new RSAPrivateKeyImpl(pemObject.getContent());
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }
    
    /**
     * Write a PEM-formatted RSA public key to a file.
     * 
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws IOException If a problem occurs while reading the file.
     */
    @Override
    public void writeRSAPublicKeyToFile(
            String filename,
            RSAPublicKey key
    ) throws TelehashException {
        try {
            PemWriter pemWriter = new PemWriter(new FileWriter(filename));
            PemObject pemObject = new PemObject(
                    RSA_PUBLIC_KEY_PEM_TYPE,
                    key.getDEREncoded()
            );
            pemWriter.writeObject(pemObject);
            pemWriter.close();
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }
    
    /**
     * Write a PEM-formatted RSA private key to a file.
     * 
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws IOException If a problem occurs while reading the file.
     */
    @Override
    public void writeRSAPrivateKeyToFile(
            String filename,
            RSAPrivateKey key
    ) throws TelehashException {
        try {
            PemWriter pemWriter = new PemWriter(new FileWriter(filename));
            PemObject pemObject = new PemObject(
                    RSA_PRIVATE_KEY_PEM_TYPE,
                    key.getDEREncoded()
            );
            pemWriter.writeObject(pemObject);
            pemWriter.close();
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Decode a DER-encoded public key into a standard Java PublicKey object.
     * 
     * @param buffer The byte buffer containing the DER-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the DER buffer cannot be parsed.
     */
    @Override
    public RSAPublicKey decodeRSAPublicKey(byte[] buffer) throws TelehashException {
        return new RSAPublicKeyImpl(buffer);
    }
    
    /**
     * Decode a DER-encoded private key into a standard Java PublicKey object.
     * 
     * @param buffer The byte buffer containing the DER-encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the DER buffer cannot be parsed.
     */
    @Override
    public RSAPrivateKey decodeRSAPrivateKey(byte[] buffer) throws TelehashException {
        return new RSAPrivateKeyImpl(buffer);
    }

    /**
     * Create a new RSAKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created RSAKeyPair object.
     */
    @Override
    public RSAKeyPair createRSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        return new RSAKeyPairImpl((RSAPublicKeyImpl)publicKey, (RSAPrivateKeyImpl)privateKey);
    }
    
    /**
     * Decode an ANSI X9.63-encoded public key into an ECPublicKey object.
     * 
     * @param buffer The byte buffer containing the ANSI X9.63-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the ANSI X9.63 buffer cannot be parsed.
     */
    @Override
    public ECPublicKey decodeECPublicKey(byte[] buffer) throws TelehashException {
        return new ECPublicKeyImpl(buffer, mECDomainParameters);
    }

    /**
     * Decode a byte-encoded private key into an ECPrivateKey object.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the byte buffer cannot be parsed.
     */
    @Override
    public ECPrivateKey decodeECPrivateKey(byte[] buffer) throws TelehashException {
        return new ECPrivateKeyImpl(buffer, mECDomainParameters);
    }

    /**
     * Create a new ECKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created ECKeyPair object.
     */
    @Override
    public ECKeyPair createECKeyPair(
            ECPublicKey publicKey,
            ECPrivateKey privateKey
    ) throws TelehashException {
        return new ECKeyPairImpl((ECPublicKeyImpl)publicKey, (ECPrivateKeyImpl)privateKey);
    }
    
    /**
     * Perform Elliptic Curve Diffie-Hellman key agreement
     * 
     * @param remotePublicKey The EC public key of the remote node.
     * @param localPrivateKey The EC private key of the local node.
     * @return A byte array containing the shared secret.
     */
    @Override
    public byte[] calculateECDHSharedSecret(
            ECPublicKey remotePublicKey,
            ECPrivateKey localPrivateKey
    ) {
        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(((ECPrivateKeyImpl)localPrivateKey).getKey());
        BigInteger secretInteger =
                agreement.calculateAgreement(((ECPublicKeyImpl)remotePublicKey).getKey());
        byte[] secretBytes = BigIntegers.asUnsignedByteArray(32, secretInteger);
        return secretBytes;
    }
    
    /**
     * Encrypt the provided plaintext using AES-256-CTR with the provided
     * initialization vector (IV) and key.
     * 
     * No padding is used. (The Telehash protocol spec calls for
     * "PKCS1 v1.5 padding", but the node.js implementation doesn't use padding.
     * Perhaps "PKCS1 v1.5 padding" is no padding?)
     * 
     * @param plainText
     *            The plaintext to encrypt.
     * @param iv
     *            The initialization vector.
     * @param key
     *            The encryption key.
     * @return The resulting ciphertext.
     * @throws TelehashException
     *             If a problem occurred.
     */
    @Override
    public byte[] encryptAES256CTR(
            byte[] plainText, 
            byte[] iv,
            byte[] key
    ) throws TelehashException {
        // initialize cipher
        AESEngine aes = new AESEngine();
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        BufferedBlockCipher cipher = new BufferedBlockCipher(new SICBlockCipher(aes));
        cipher.init(true, ivAndKey);

        // encrypt
        byte[] cipherText = new byte[cipher.getOutputSize(plainText.length)];
        int nbytes = cipher.processBytes(plainText, 0, plainText.length, cipherText, 0);
        try {
            nbytes += cipher.doFinal(cipherText, nbytes);
        } catch (CryptoException e) {
            throw new TelehashException(e);
        }
        
        // trim output if needed
        if (nbytes < cipherText.length) {
            byte[] trimmedCipherText = new byte[nbytes];
            System.arraycopy(cipherText, 0, trimmedCipherText, 0, nbytes);
            cipherText = trimmedCipherText;
        }

        return cipherText;
    }

    /**
     * Decrypt the provided ciphertext using AES-256-CTR with the provided
     * initialization vector (IV) and key.
     * 
     * No padding is used. (The Telehash protocol spec calls for
     * "PKCS1 v1.5 padding", but the node.js implementation doesn't use padding.
     * Perhaps "PKCS1 v1.5 padding" is no padding?)

     * @param plainText The ciphertext to decrypt.
     * @param iv The initialization vector.
     * @param key The encryption key.
     * @return The resulting plaintext.
     * @throws TelehashException If a problem occurred.
     */
    @Override
    public byte[] decryptAES256CTR(
            byte[] cipherText, 
            byte[] iv,
            byte[] key
    ) throws TelehashException {
        // init cipher
        AESEngine aes = new AESEngine();
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        BufferedBlockCipher cipher = new BufferedBlockCipher(new SICBlockCipher(aes));
        cipher.init(false, ivAndKey);

        // decrypt
        byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
        int nbytes = cipher.processBytes(cipherText, 0, cipherText.length, plainText, 0);
        try {
            nbytes += cipher.doFinal(plainText, nbytes);
        } catch (CryptoException e) {
            throw new TelehashException(e);
        }
        
        // trim output if needed
        if (nbytes < plainText.length) {
            byte[] trimmedPlainText = new byte[nbytes];
            System.arraycopy(plainText, 0, trimmedPlainText, 0, nbytes);
            plainText = trimmedPlainText;
        }

        return plainText;
    }

}
