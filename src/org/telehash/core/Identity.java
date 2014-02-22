package org.telehash.core;

import org.telehash.crypto.RSAKeyPair;
import org.telehash.crypto.RSAPrivateKey;
import org.telehash.crypto.RSAPublicKey;

/**
 * An object of this class represents the identity of the local Telehash node.
 */
public class Identity {
    private RSAKeyPair mKeyPair;
    //private transient byte[] mHashName;
    private transient HashName mHashName;

    /**
     * Create an Identity object based on the provided RSA key pair.
     * @param keyPair
     */
    public Identity(RSAKeyPair keyPair) {
        mKeyPair = keyPair;
        try {
            byte[] hashNameBytes = Telehash.get().getCrypto().sha256Digest(
                    mKeyPair.getPublicKey().getDEREncoded()
            );
            mHashName = new HashName(hashNameBytes);
        } catch (TelehashException e) {
            e.printStackTrace();
            mHashName = null;
        }
    }
    
    /**
     * Return the RSA private key of this identity.
     * @return The private key.
     */
    public RSAPrivateKey getPrivateKey() {
        return mKeyPair.getPrivateKey();
    }
    
    /**
     * Return the RSA public key of this identity.
     * @return The public key.
     */
    public RSAPublicKey getPublicKey() {
        return mKeyPair.getPublicKey();
    }

    /**
     * Return the hashname of this identity, which is a SHA-256 digest of the
     * public key.
     * 
     * @return The hashname.
     */
    public HashName getHashName() {
        return mHashName;
    }    
}
