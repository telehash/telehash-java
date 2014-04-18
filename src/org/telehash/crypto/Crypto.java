package org.telehash.crypto;

import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.LocalNode;
import org.telehash.core.TelehashException;

import java.util.NavigableSet;
import java.util.Set;

/**
 * This interface contains the basic cryptographic functions required by
 * Telehash. Concrete implementations suitable for specific platforms may be
 * developed, and applications are free to extend these implementations or
 * provide their own.
 */
public interface Crypto {

    /**
     * Return the cipher set associated with the provided cipher set id.
     * @param cipherSetId
     * @return The cipher set implementation, or null if no cipher set
     * matches the id.
     */
    public CipherSet getCipherSet(CipherSetIdentifier cipherSetId);

    /**
     * Return the set of all supported cipher sets.
     * @return The set of cipher sets.
     */
    public Set<CipherSet> getAllCipherSets();

    /**
     * Return the set of all supported cipher sets ids.
     * @return The set of cipher set identifiers.
     */
    public NavigableSet<CipherSetIdentifier> getAllCipherSetsIds();

    /**
     * Generate a cryptographically secure pseudo-random array of byte values.
     *
     * @param size The number of random bytes to produce.
     * @return The array of random byte values.
     */
    public byte[] getRandomBytes(int size);

    /**
     * Return a SHA-256 digest of the provided byte buffer.
     *
     * @param buffer The buffer to digest.
     * @return A 32-byte array representing the digest.
     */
    public byte[] sha256Digest(byte[] buffer);

    /**
     * Return a SHA-256 digest of the provided UTF-8 string.
     *
     * @param string The string to digest.
     * @return A 32-byte array representing the digest.
     */
    public byte[] sha256Digest(String string);

    /**
     * Generate a fresh local node (i.e., public and private key pair) for a
     * newly provisioned Telehash node.
     *
     * @return The new local node.
     * @throws TelehashException
     */
    public LocalNode generateLocalNode() throws TelehashException;

    /**
     * Encrypt data with an RSA public key
     * @throws TelehashException
     */
    public byte[] encryptRSAOAEP(HashNamePublicKey key, byte[] clearText) throws TelehashException;

    /**
     * Decrypt data with an RSA private key
     * @throws TelehashException
     */
    public byte[] decryptRSAOAEP(HashNamePrivateKey key, byte[] buffer) throws TelehashException;

    /**
     * Sign a data buffer with an RSA private key using the SHA-256 digest, and
     * PKCSv1.5 padding.
     *
     * @throws TelehashException
     */
    public byte[] signRSA(HashNamePrivateKey key, byte[] buffer) throws TelehashException;

    /**
     * Verify the signature of a data buffer with an RSA private key using the
     * SHA-256 digest, and PKCSv1.5 padding.
     *
     * @return true if the signature is valid; false otherwise.
     * @throws TelehashException
     */
    public boolean verifyRSA(
            HashNamePublicKey key,
            byte[] buffer,
            byte[] signature
    ) throws TelehashException;

    /**
     * Create a new ECKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created ECKeyPair object.
     */
    public LineKeyPair createECKeyPair(
            LinePublicKey publicKey,
            LinePrivateKey privateKey
    ) throws TelehashException;

    /**
     * Create a new HashNameKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created HashNameKeyPair object.
     */
    public HashNameKeyPair createHashNameKeyPair(
            HashNamePublicKey publicKey,
            HashNamePrivateKey privateKey
    );
}
