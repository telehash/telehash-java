package org.telehash.core;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.JCERSAPrivateKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;

/**
 * An object of this class represents the identity of the local Telehash node.
 */
public class Identity {
    private KeyPair mKeyPair;
    private transient byte[] mHashName;

    /**
     * Create an Identity object based on the provided RSA key pair.
     * @param keyPair
     */
    public Identity(KeyPair keyPair) {
        // verify the crypto provider gave us keys of the expected classes.
        if (! (keyPair.getPrivate() instanceof JCERSAPrivateKey)) {
            throw new RuntimeException("ouch"); // TODO
        }
        if (! (keyPair.getPublic() instanceof JCERSAPublicKey)) {
            throw new RuntimeException("ouch"); // TODO            
        }

        mKeyPair = keyPair;
        
        JCERSAPublicKey publicKey = (JCERSAPublicKey)(keyPair.getPublic());
        // TODO: check for null from sha256Digest
        mHashName = Util.getCryptoInstance().sha256Digest(publicKey.getEncoded());
    }
    
    /**
     * Return the RSA private key of this identity.
     * @return The private key.
     */
    public PrivateKey getPrivateKey() {
        return mKeyPair.getPrivate();
    }
    
    /**
     * Return the RSA public key of this identity.
     * @return The public key.
     */
    public PublicKey getPublicKey() {
        return mKeyPair.getPublic();
    }

    /**
     * Return the hashname of this identity, which is a SHA-256 digest of the
     * public key.
     * 
     * @return The hashname.
     */
    public byte[] getHashName() {
        return mHashName;
    }
}
