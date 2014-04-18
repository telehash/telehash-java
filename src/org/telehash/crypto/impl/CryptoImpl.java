package org.telehash.crypto.impl;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.LocalNode;
import org.telehash.core.TelehashException;
import org.telehash.crypto.CipherSet;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.crypto.LineKeyPair;
import org.telehash.crypto.LinePrivateKey;
import org.telehash.crypto.LinePublicKey;
import org.telehash.crypto.set2a.CipherSet2aImpl;
import org.telehash.crypto.set2a.HashNamePrivateKeyImpl;
import org.telehash.crypto.set2a.HashNamePublicKeyImpl;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashSet;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * This class contains implementations for the basic cryptographic functions
 * needed by Telehash.
 */
public class CryptoImpl implements Crypto {

    private static final String RSA_PRIVATE_KEY_PEM_TYPE = "RSA PRIVATE KEY";
    private static final String RSA_PUBLIC_KEY_PEM_TYPE = "PUBLIC KEY";

    // a simple cipher set registration scheme
    private SortedMap<CipherSetIdentifier,CipherSet> mCipherSetMap =
            new TreeMap<CipherSetIdentifier,CipherSet>();

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
        // populate the cipher set map
        CipherSet2aImpl set2a = new CipherSet2aImpl(this);
        mCipherSetMap.put(set2a.getCipherSetId(), set2a);

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
     * Return the set of all supported cipher sets.
     * @return The set of cipher sets.
     */
    @Override
    public Set<CipherSet> getAllCipherSets() {
        return new HashSet<CipherSet>(mCipherSetMap.values());
    }

    /**
     * Return the set of all supported cipher sets ids.
     * @return The set of cipher set identifiers.
     */
    @Override
    public NavigableSet<CipherSetIdentifier> getAllCipherSetsIds() {
        return new TreeSet<CipherSetIdentifier>(mCipherSetMap.keySet());
    }

    /**
     * Return the cipher set associated with the provided cipher set id.
     * @param cipherSetId
     * @return The cipher set implementation, or null if no cipher set
     * matches the id.
     */
    @Override
    public CipherSet getCipherSet(CipherSetIdentifier cipherSetId) {
        if (cipherSetId == null) {
            return null;
        }
        return mCipherSetMap.get(cipherSetId);
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
     * Return a SHA-256 digest of the provided UTF-8 string.
     *
     * @param string The string to digest.
     * @return A 32-byte array representing the digest.
     */
    @Override
    public byte[] sha256Digest(String string) {
        return sha256Digest(string.getBytes(Charset.forName("UTF-8")));
    }

    /**
     * Generate fresh local node keys for a newly provisioned Telehash node.
     *
     * @return The new local node.
     * @throws TelehashException
     */
    @Override
    public LocalNode generateLocalNode() throws TelehashException {
        // Note: this iteration is implicitly sorted by ascending keys via TreeSet.
        SortedMap<CipherSetIdentifier,HashNameKeyPair> keyPairs =
                new TreeMap<CipherSetIdentifier,HashNameKeyPair>();
        for (Map.Entry<CipherSetIdentifier, CipherSet> entry : mCipherSetMap.entrySet()) {
            CipherSetIdentifier cipherSetId = entry.getKey();
            CipherSet cipherSet = entry.getValue();
            HashNameKeyPair hashNameKeyPair = cipherSet.generateHashNameKeyPair();
            keyPairs.put(cipherSetId, hashNameKeyPair);
        }
        return new LocalNode(keyPairs);
    }

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
     * Decrypt data with an RSA private key and OAEP padding
     * @throws TelehashException
     */
    @Override
    public byte[] decryptRSAOAEP(
            HashNamePrivateKey key,
            byte[] cipherText
    ) throws TelehashException {
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
     * Create a new HashNameKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created HashNameKeyPair object.
     */
    @Override
    public HashNameKeyPair createHashNameKeyPair(
            HashNamePublicKey publicKey,
            HashNamePrivateKey privateKey
    ) {
        CipherSetIdentifier csid = publicKey.getCipherSetIdentifier();
        if (! csid.equals(privateKey.getCipherSetIdentifier())) {
            throw new IllegalArgumentException("cipher set mismatch");
        }
        return getCipherSet(csid).createHashNameKeyPair(publicKey, privateKey);
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
        CipherSetIdentifier csid = publicKey.getCipherSetIdentifier();
        if (! csid.equals(privateKey.getCipherSetIdentifier())) {
            throw new IllegalArgumentException("cipher set mismatch");
        }
        return getCipherSet(csid).createLineKeyPair(publicKey, privateKey);
    }
}
