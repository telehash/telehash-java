package org.telehash.crypto;

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
     * Generate a fresh identity (i.e., RSA public and private key pair) for a
     * newly provisioned Telehash node.
     * 
     * @return The new identity.
     * @throws TelehashException 
     */
    public Identity generateIdentity() throws TelehashException;
    
    /**
     * Generate a fresh elliptic curve key pair
     * @throws TelehashException 
     */
    public ECKeyPair generateECKeyPair() throws TelehashException;
    
    /**
     * Encrypt data with an RSA public key
     * @throws TelehashException 
     */
    public byte[] encryptRSA(RSAPublicKey key, byte[] buffer) throws TelehashException;

    /**
     * Decrypt data with an RSA private key
     * @throws TelehashException 
     */
    public byte[] decryptRSA(RSAPrivateKey key, byte[] buffer) throws TelehashException;

    /**
     * Read a PEM-formatted RSA public key from a file.
     * 
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public RSAPublicKey readRSAPublicKeyFromFile(String filename) throws TelehashException;

    /**
     * Read a PEM-formatted RSA private key from a file.
     * 
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public RSAPrivateKey readRSAPrivateKeyFromFile(String filename) throws TelehashException;

    /**
     * Write a PEM-formatted RSA public key to a file.
     * 
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public void writeRSAPublicKeyToFile(
            String filename,
            RSAPublicKey key
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
            RSAPrivateKey key
    ) throws TelehashException;

    /**
     * Decode a DER-encoded public key into a standard Java PublicKey object.
     * 
     * @param buffer The byte buffer containing the DER-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the DER buffer cannot be parsed.
     */
    public RSAPublicKey decodeRSAPublicKey(byte[] buffer) throws TelehashException;

    /**
     * Decode a DER-encoded private key into a standard Java PublicKey object.
     * 
     * @param buffer The byte buffer containing the DER-encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the DER buffer cannot be parsed.
     */
    public RSAPrivateKey decodeRSAPrivateKey(byte[] buffer) throws TelehashException;

    /**
     * Decode an ANSI X9.63-encoded public key into an ECPublicKey object.
     * 
     * @param buffer The byte buffer containing the ANSI X9.63-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the ANSI X9.63 buffer cannot be parsed.
     */
    public ECPublicKey decodeECPublicKey(byte[] buffer) throws TelehashException;

    /**
     * Decode an ANSI X9.63-encoded private key into an ECPrivateKey object.
     * 
     * @param buffer The byte buffer containing the ANSI X9.63-encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the ANSI X9.63 buffer cannot be parsed.
     */
    //public ECPrivateKey decodeECPrivateKey(byte[] buffer) throws TelehashException;

    /**
     * Create a new RSAKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created RSAKeyPair object.
     */
    public RSAKeyPair createRSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey);
    
    /**
     * Perform Elliptic Curve Diffie-Hellman key agreement
     * 
     * @param remotePublicKey The EC public key of the remote node.
     * @param localPrivateKey The EC private key of the local node.
     * @return A byte array containing the shared secret.
     */
    public byte[] calculateECDHSharedSecret(
            ECPublicKey remotePublicKey,
            ECPrivateKey localPrivateKey
    );
}
