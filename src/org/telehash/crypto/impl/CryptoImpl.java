package org.telehash.crypto.impl;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
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
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
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
import org.telehash.crypto.CipherSet;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.LineKeyPair;
import org.telehash.crypto.LinePrivateKey;
import org.telehash.crypto.LinePublicKey;
import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.crypto.set2a.CipherSet2aImpl;
import org.telehash.crypto.set2a.HashNamePrivateKeyImpl;
import org.telehash.crypto.set2a.HashNamePublicKeyImpl;
import org.telehash.crypto.set2a.LinePrivateKeyImpl;
import org.telehash.crypto.set2a.LinePublicKeyImpl;

/**
 * This class contains implementations for the basic cryptographic functions
 * needed by Telehash.
 */
public class CryptoImpl implements Crypto {
    
    private static final String RSA_PRIVATE_KEY_PEM_TYPE = "RSA PRIVATE KEY";
    private static final String RSA_PUBLIC_KEY_PEM_TYPE = "PUBLIC KEY";
    
    // we only use the 2a cipher set for now.
    private CipherSet mCipherSet = new CipherSet2aImpl(this);
    
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
     * TODO: REMOVE!!!
     * @deprecated
     */
    @Override
	public CipherSet getCipherSet() {
		return mCipherSet;
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
     * Generate a fresh identity (i.e., hashname public and private key pair)
     * for a newly provisioned Telehash node.
     * 
     * @return The new identity.
     * @throws TelehashException 
     */
    @Override
    public Identity generateIdentity() throws TelehashException {
    	return mCipherSet.generateIdentity();
    }

    /**
     * Generate a fresh line key pair
     */
    @Override
    public LineKeyPair generateLineKeyPair() throws TelehashException {
    	return mCipherSet.generateLineKeyPair();
    }
    
    /**
     * Encrypt data with an RSA private key
     * @throws TelehashException 
     */
    /*
    @Override
    public byte[] encryptRSA(HashNamePublicKey key, byte[] clearText) throws TelehashException {
        AsymmetricBlockCipher cipher = new RSAEngine();
        cipher.init(true, ((HashNamePublicKeyImpl)key).getKey());
        byte[] cipherText;
        try {
            cipherText = cipher.processBlock(clearText, 0, clearText.length);
        } catch (InvalidCipherTextException e) {
            throw new TelehashException(e);
        }
        return cipherText;
    }
    */
    
    /**
     * Encrypt data with an RSA private key using OAEP padding
     * @throws TelehashException 
     */
    @Override
    public byte[] encryptRSAOAEP(HashNamePublicKey key, byte[] clearText) throws TelehashException {
        AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        cipher.init(true, ((HashNamePublicKeyImpl)key).getKey());
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
    /*
    @Override
    public byte[] decryptRSA(HashNamePrivateKey key, byte[] cipherText) throws TelehashException {
        AsymmetricBlockCipher cipher = new RSAEngine();
        cipher.init(false, ((HashNamePrivateKeyImpl)key).getKey());
        byte[] clearText;
        try {
            clearText = cipher.processBlock(cipherText, 0, cipherText.length);
        } catch (InvalidCipherTextException e) {
            throw new TelehashException(e);
        }
        return clearText;
    }
    */

    /**
     * Decrypt data with an RSA private key and OAEP padding
     * @throws TelehashException 
     */
    @Override
    public byte[] decryptRSAOAEP(HashNamePrivateKey key, byte[] cipherText) throws TelehashException {
        AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest());
        cipher.init(false, ((HashNamePrivateKeyImpl)key).getKey());
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
    public byte[] signRSA(HashNamePrivateKey key, byte[] buffer) throws TelehashException {
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(true, ((HashNamePrivateKeyImpl)key).getKey());
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
            HashNamePublicKey key,
            byte[] buffer,
            byte[] signature
    ) throws TelehashException {
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(false, ((HashNamePublicKeyImpl)key).getKey());
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
    public HashNamePublicKey parseRSAPublicKeyFromPEM(String pem) throws TelehashException {
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
            return new HashNamePublicKeyImpl(PublicKeyFactory.createKey(pemObject.getContent()));
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
    public HashNamePublicKey readRSAPublicKeyFromFile(String filename) throws TelehashException {
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
            return new HashNamePublicKeyImpl(PublicKeyFactory.createKey(pemObject.getContent()));
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
    public HashNamePrivateKey readRSAPrivateKeyFromFile(String filename) throws TelehashException {
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
            return new HashNamePrivateKeyImpl(pemObject.getContent());
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
            HashNamePublicKey key
    ) throws TelehashException {
        try {
            PemWriter pemWriter = new PemWriter(new FileWriter(filename));
            PemObject pemObject = new PemObject(
                    RSA_PUBLIC_KEY_PEM_TYPE,
                    key.getEncoded()
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
            HashNamePrivateKey key
    ) throws TelehashException {
        try {
            PemWriter pemWriter = new PemWriter(new FileWriter(filename));
            PemObject pemObject = new PemObject(
                    RSA_PRIVATE_KEY_PEM_TYPE,
                    key.getEncoded()
            );
            pemWriter.writeObject(pemObject);
            pemWriter.close();
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Decode a public key.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the buffer cannot be parsed.
     */
    @Override
    public HashNamePublicKey decodeHashNamePublicKey(byte[] buffer) throws TelehashException {
    	return mCipherSet.decodeHashNamePublicKey(buffer);
    }
    
    /**
     * Decode a private key.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the buffer cannot be parsed.
     */
    @Override
    public HashNamePrivateKey decodeHashNamePrivateKey(byte[] buffer) throws TelehashException {
    	return mCipherSet.decodeHashNamePrivateKey(buffer);
    }

    /**
     * Create a new HashNameKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created HashNameKeyPair object.
     */
    @Override
    public HashNameKeyPair createHashNameKeyPair(HashNamePublicKey publicKey, HashNamePrivateKey privateKey) {
    	return mCipherSet.createHashNameKeyPair(publicKey, privateKey);
    }
    
    /**
     * Decode an ANSI X9.63-encoded public key into an ECPublicKey object.
     * 
     * @param buffer The byte buffer containing the ANSI X9.63-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the ANSI X9.63 buffer cannot be parsed.
     */
    @Override
    public LinePublicKey decodeLinePublicKey(byte[] buffer) throws TelehashException {
    	return mCipherSet.decodeLinePublicKey(buffer);
    }

    /**
     * Decode a byte-encoded private key into an ECPrivateKey object.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the byte buffer cannot be parsed.
     */
    @Override
    public LinePrivateKey decodeLinePrivateKey(byte[] buffer) throws TelehashException {
    	return mCipherSet.decodeLinePrivateKey(buffer);
    }

    /**
     * Create a new ECKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created ECKeyPair object.
     */
    @Override
    public LineKeyPair createECKeyPair(
            LinePublicKey publicKey,
            LinePrivateKey privateKey
    ) throws TelehashException {
    	return mCipherSet.createLineKeyPair(publicKey, privateKey);
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
            LinePublicKey remotePublicKey,
            LinePrivateKey localPrivateKey
    ) {
        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(((LinePrivateKeyImpl)localPrivateKey).getKey());
        BigInteger secretInteger =
                agreement.calculateAgreement(((LinePublicKeyImpl)remotePublicKey).getKey());
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
