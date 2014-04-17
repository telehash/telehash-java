package org.telehash.core;

import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.Path;

import java.util.Map;
import java.util.TreeMap;

/**
 * An object of this class represents the identity of the local Telehash node.
 */
public class Identity {
    private Map<CipherSetIdentifier,HashNameKeyPair> mKeyPairs =
            new TreeMap<CipherSetIdentifier,HashNameKeyPair>();
    private transient HashName mHashName;

    /**
     * Create an Identity object based on the provided RSA key pair.
     * @param keyPair
     */
    public Identity(Map<CipherSetIdentifier,HashNameKeyPair> keyPairs) {
        mKeyPairs.putAll(keyPairs);

        try {
            mHashName = HashName.calculateHashName(getHashNamePublicKeys());
        } catch (TelehashException e) {
            e.printStackTrace();
            mHashName = null;
        }
    }

    /**
     * Return a map of all hashname key pairs (keyed by cipher set id).
     *
     * @return A map of all hashname key pairs.
     */
    public Map<CipherSetIdentifier,HashNameKeyPair> getHashNameKeyPairs() {
        return mKeyPairs;
    }

    /**
     * Return a map of hashname public keys (keyed by cipher set id).
     *
     * @return A map of hashname public keys.
     */
    public Map<CipherSetIdentifier,HashNamePublicKey> getHashNamePublicKeys() {
        // create a map of public keys from the map of key pairs
        Map<CipherSetIdentifier,HashNamePublicKey> publicKeys =
                new TreeMap<CipherSetIdentifier,HashNamePublicKey>();
        for (Map.Entry<CipherSetIdentifier,HashNameKeyPair> entry : mKeyPairs.entrySet()) {
            publicKeys.put(entry.getKey(), entry.getValue().getPublicKey());
        }
        return publicKeys;
    }

    /**
     * Return the hashname public key for the indicated cipher set.
     *
     * @param csid The cipher set id.
     * @return The hashname public key.
     */
    public HashNamePublicKey getHashNamePublicKey(CipherSetIdentifier csid) {
        HashNameKeyPair keyPair = mKeyPairs.get(csid);
        if (keyPair == null) {
            return null;
        }
        return keyPair.getPublicKey();
    }

    /**
     * Return the hashname private key for the indicated cipher set.
     *
     * @param csid The cipher set id.
     * @return The hashname private key.
     */
    public HashNamePrivateKey getHashNamePrivateKey(CipherSetIdentifier csid) {
        HashNameKeyPair keyPair = mKeyPairs.get(csid);
        if (keyPair == null) {
            return null;
        }
        return keyPair.getPrivateKey();
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
            return new Node(getHashNamePublicKeys(), null);
        } catch (TelehashException e) {
            return null;
        }
    }

    /**
     * Return a node representation of this identity with the specified path.
     */
    public Node getNode(Path path) {
        try {
            return new Node(getHashNamePublicKeys(), path);
        } catch (TelehashException e) {
            return null;
        }
    }
}
