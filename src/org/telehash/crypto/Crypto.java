package org.telehash.crypto;

import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.Identity;
import org.telehash.core.TelehashException;

/**
 * This interface contains the basic cryptographic functions required by
 * Telehash. Concrete implementations suitable for specific platforms may be
 * developed, and applications are free to extend these implementations or
 * provide their own.
 */
public interface Crypto {

    /**
     * TODO: REMOVE!!!
     * @deprecated
     */
    @Deprecated
    public CipherSet getCipherSet();

    /**
     * Return the cipher set associated with the provided cipher set id.
     * @param cipherSetId
     * @return The cipher set implementation, or null if no cipher set
     * matches the id.
     */
    public CipherSet getCipherSet(CipherSetIdentifier cipherSetId);

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
     * Generate a fresh identity (i.e., RSA public and private key pair) for a
     * newly provisioned Telehash node.
     *
     * @return The new identity.
     * @throws TelehashException
     */
    public Identity generateIdentity() throws TelehashException;

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
     * Parse a PEM-formatted RSA public key
     *
     * @param pem The PEM string.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    HashNamePublicKey parseRSAPublicKeyFromPEM(String pem) throws TelehashException;

    /**
     * Read a PEM-formatted RSA public key from a file.
     *
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public HashNamePublicKey readRSAPublicKeyFromFile(String filename) throws TelehashException;

    /**
     * Read a PEM-formatted RSA private key from a file.
     *
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public HashNamePrivateKey readRSAPrivateKeyFromFile(String filename) throws TelehashException;

    /**
     * Write a PEM-formatted RSA public key to a file.
     *
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public void writeRSAPublicKeyToFile(
            String filename,
            HashNamePublicKey key
    ) throws TelehashException;

    /**
     * Write a PEM-formatted RSA private key to a file.
     *
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public void writeRSAPrivateKeyToFile(
            String filename,
            HashNamePrivateKey key
    ) throws TelehashException;

    /**
     * Decode a DER-encoded public key into a standard Java PublicKey object.
     *
     * @param buffer The byte buffer containing the DER-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the DER buffer cannot be parsed.
     */
    public HashNamePublicKey decodeHashNamePublicKey(byte[] buffer) throws TelehashException;

    /**
     * Decode a DER-encoded private key into a standard Java PublicKey object.
     *
     * @param buffer The byte buffer containing the DER-encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the DER buffer cannot be parsed.
     */
    public HashNamePrivateKey decodeHashNamePrivateKey(byte[] buffer) throws TelehashException;

    /**
     * Decode an ANSI X9.63-encoded public key into an ECPublicKey object.
     *
     * @param buffer The byte buffer containing the ANSI X9.63-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the ANSI X9.63 buffer cannot be parsed.
     */
    public LinePublicKey decodeLinePublicKey(byte[] buffer) throws TelehashException;

    /**
     * Decode a byte-encoded private key into an ECPrivateKey object.
     *
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the byte buffer cannot be parsed.
     */
    public LinePrivateKey decodeLinePrivateKey(byte[] buffer) throws TelehashException;

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
