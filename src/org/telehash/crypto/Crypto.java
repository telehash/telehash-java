package org.telehash.crypto;

import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;

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
     */
    public Identity generateIdentity();
    
    /**
     * Read a PEM-formatted key from a file.
     * 
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws IOException If a problem occurs while reading the file.
     */
    public Key readKeyFromFile(String filename) throws IOException;

    /**
     * Write a PEM-formatted key to a file.
     * 
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws IOException If a problem occurs while reading the file.
     */
    public void writeKeyToFile(String filename, Key key) throws IOException;

    /**
     * Decode a DER-encoded public key into a standard Java PublicKey object.
     * 
     * @param buffer The byte buffer containing the DER-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the DER buffer cannot be parsed.
     */
    public PublicKey derToRSAPublicKey(byte[] buffer) throws TelehashException;
}
