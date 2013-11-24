package org.telehash.crypto.impl;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.telehash.core.Identity;
import org.telehash.core.TelehashException;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.ECKeyPair;
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
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    };

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
    public ECKeyPair generateECCKeyPair() throws TelehashException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance("ECDH", "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new TelehashException(e);
        } catch (NoSuchProviderException e) {
            throw new TelehashException(e);
        }
        try {
            generator.initialize(ecGenSpec, new SecureRandom());
        } catch (InvalidAlgorithmParameterException e) {
            throw new TelehashException(e);
        }
        return new ECKeyPairImpl(generator.generateKeyPair());
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
        System.out.println("read file: "+filename);
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
            AsymmetricKeyParameter key = PrivateKeyFactory.createKey(pemObject.getContent());
            if (! (key instanceof RSAPrivateCrtKeyParameters)) {
                throw new TelehashException("parsed key was not a proper RSA private key.");
            }
            return new RSAPrivateKeyImpl((RSAPrivateCrtKeyParameters)key);
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
}
