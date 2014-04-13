package org.telehash.core;

import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;

/**
 * An object of this class represents the identity of the local Telehash node.
 */
public class Identity {
    private HashNameKeyPair mKeyPair;
    private transient HashName mHashName;

    /**
     * Create an Identity object based on the provided RSA key pair.
     * @param keyPair
     */
    public Identity(HashNameKeyPair keyPair) {
        mKeyPair = keyPair;
        try {
            byte[] hashNameBytes = Telehash.get().getCrypto().sha256Digest(
                    mKeyPair.getPublicKey().getEncoded()
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
    public HashNamePrivateKey getPrivateKey() {
        return mKeyPair.getPrivateKey();
    }

    /**
     * Return the RSA public key of this identity.
     * @return The public key.
     */
    public HashNamePublicKey getPublicKey() {
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

    /**
     * Return a node representation of this identity.
     */
    public Node getNode() {
        try {
            return new Node(mKeyPair.getPublicKey(), null);
        } catch (TelehashException e) {
            return null;
        }
    }
}
