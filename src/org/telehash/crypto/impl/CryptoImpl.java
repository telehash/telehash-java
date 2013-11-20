package org.telehash.crypto.impl;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKKeyPairGenerator;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.telehash.core.Identity;
import org.telehash.core.TelehashException;
import org.telehash.crypto.Crypto;

/**
 * This class contains implementations for the basic cryptographic functions
 * needed by Telehash.
 */
public class CryptoImpl implements Crypto {
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    };

    /**
     * Return a SHA-256 digest of the provided byte buffer.
     * 
     * @param buffer The buffer to digest.
     * @return A 32-byte array representing the digest.
     */
    public byte[] sha256Digest(byte[] buffer) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256", "BC");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        digest.update(buffer);
        return digest.digest();
    }

    /**
     * Generate a fresh identity (i.e., RSA public and private key pair) for a
     * newly provisioned Telehash node.
     * 
     * @return The new identity.
     */
    public Identity generateIdentity() {
        // generate a 2048 bit key pair
        JDKKeyPairGenerator.RSA keyPairGen = new JDKKeyPairGenerator.RSA();
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        
        // construct the identity
        return new Identity(keyPair);
    }

    /**
     * Read a PEM-formatted key from a file.
     * 
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws IOException If a problem occurs while reading the file.
     */
    public Key readKeyFromFile(String filename) throws IOException {
        PEMReader pemReader = new PEMReader(new FileReader(filename));
        Object object = pemReader.readObject();
        pemReader.close();
        if (object == null) {
            throw new IOException("Empty PEM file.");
        } else if (object instanceof Key) {
            return (Key)object;
        } else if (object instanceof KeyPair) {
            // extract the private key from a key pair
            return ((KeyPair)object).getPrivate();
        } else {
            throw new IOException(
                    "Unknown object type \""+object.getClass()+"\" read from PEM file."
            );
        }
    }
    
    /**
     * Write a PEM-formatted key to a file.
     * 
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws IOException If a problem occurs while reading the file.
     */
    public void writeKeyToFile(String filename, Key key) throws IOException {
        PEMWriter pemWriter = new PEMWriter(new FileWriter(filename));
        pemWriter.writeObject(key);
        pemWriter.close();
    }

    /**
     * Decode a DER-encoded public key into a standard Java PublicKey object.
     * 
     * @param buffer The byte buffer containing the DER-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the DER buffer cannot be parsed.
     */
    public PublicKey derToRSAPublicKey(byte[] buffer) throws TelehashException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(buffer);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            return keyFactory.generatePublic(spec);
        } catch (NoSuchProviderException e) {
            throw new TelehashException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new TelehashException(e);
        } catch (InvalidKeySpecException e) {
            throw new TelehashException(e);
        }
    }
}
