package org.telehash.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.telehash.core.Identity;
import org.telehash.core.LineIdentifier;
import org.telehash.core.OpenPacket;
import org.telehash.core.TelehashException;
import org.telehash.core.UnwrappedOpenPacket;
import org.telehash.crypto.set2a.LineKeyPairImpl;
import org.telehash.crypto.set2a.LinePrivateKeyImpl;
import org.telehash.crypto.set2a.LinePublicKeyImpl;
import org.telehash.network.Path;

public interface CipherSet {

    /**
     * Generate a fresh identity (i.e., RSA public and private key pair) for a
     * newly provisioned Telehash node.
     * 
     * @return The new identity.
     * @throws TelehashException 
     */
    public Identity generateIdentity() throws TelehashException;

    /**
     * Create a new HashNameKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created HashNameKeyPair object.
     */
    public HashNameKeyPair createHashNameKeyPair(HashNamePublicKey publicKey, HashNamePrivateKey privateKey);

    /**
     * Decode a hashname public key.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the buffer cannot be parsed.
     */
    public HashNamePublicKey decodeHashNamePublicKey(byte[] buffer) throws TelehashException;
    
    /**
     * Decode a hashname private key.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the buffer cannot be parsed.
     */
    public HashNamePrivateKey decodeHashNamePrivateKey(byte[] buffer) throws TelehashException;

    /**
     * Decode a line public key.
     * 
     * @param buffer The byte buffer containing the ANSI X9.63-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the ANSI X9.63 buffer cannot be parsed.
     */
    public LinePublicKey decodeLinePublicKey(byte[] buffer) throws TelehashException;

    /**
     * Decode a line private key.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the byte buffer cannot be parsed.
     */
    public LinePrivateKey decodeLinePrivateKey(byte[] buffer) throws TelehashException;

    /**
     * Create a new line key pair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created key pair.
     */
    public LineKeyPair createLineKeyPair(
            LinePublicKey publicKey,
            LinePrivateKey privateKey
    ) throws TelehashException;
    
    /**
     * Generate a fresh elliptic curve key pair
     */
    public LineKeyPair generateLineKeyPair() throws TelehashException;
    
    public UnwrappedOpenPacket unwrapOpenPacket(
    		HashNamePrivateKey hashNamePrivateKey,
    		byte[] iv,
    		byte[] encryptedSignature,
    		byte[] openParameter,
    		byte[] encryptedInnerPacket,
    		Path path
    ) throws TelehashException;
    
    public OpenPacket verifyOpenPacket(
    		UnwrappedOpenPacket unwrappedOpenPacket,
    		byte[] destination,
    		byte[] lineIdentifierBytes,
    		LineIdentifier lineIdentifier,
    		long openTime,
    		byte[] innerPacketBody
    ) throws TelehashException;
}
