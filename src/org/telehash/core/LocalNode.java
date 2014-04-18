package org.telehash.core;

import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;

import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * An object of this class represents the parameters of the local Telehash node.
 */
public class LocalNode extends FullNode {
    private SortedMap<CipherSetIdentifier,HashNamePrivateKey> mPrivateKeys;

    /**
     * Create a LocalNode object based on the provided RSA key pair.
     * @param keyPair
     */
    public LocalNode(SortedMap<CipherSetIdentifier,HashNameKeyPair> keyPairs) {
        super(extractPublicKeys(keyPairs), /* paths */ null);
        mPrivateKeys = extractPrivateKeys(keyPairs);
    }

    private static SortedMap<CipherSetIdentifier,HashNamePublicKey> extractPublicKeys(
            SortedMap<CipherSetIdentifier,HashNameKeyPair> keyPairs
    ) {
        SortedMap<CipherSetIdentifier,HashNamePublicKey> publicKeys =
                new TreeMap<CipherSetIdentifier,HashNamePublicKey>();
        for (Map.Entry<CipherSetIdentifier,HashNameKeyPair> entry : keyPairs.entrySet()) {
            publicKeys.put(entry.getKey(), entry.getValue().getPublicKey());
        }
        return publicKeys;
    }

    private static SortedMap<CipherSetIdentifier,HashNamePrivateKey> extractPrivateKeys(
            SortedMap<CipherSetIdentifier,HashNameKeyPair> keyPairs
    ) {
        SortedMap<CipherSetIdentifier,HashNamePrivateKey> privateKeys =
                new TreeMap<CipherSetIdentifier,HashNamePrivateKey>();
        for (Map.Entry<CipherSetIdentifier,HashNameKeyPair> entry : keyPairs.entrySet()) {
            privateKeys.put(entry.getKey(), entry.getValue().getPrivateKey());
        }
        return privateKeys;
    }

    /**
     * Return a map of all hashname key pairs (keyed by cipher set id).
     *
     * @return A map of all hashname key pairs.
     */
    public SortedMap<CipherSetIdentifier,HashNameKeyPair> getHashNameKeyPairs() {
        SortedMap<CipherSetIdentifier,HashNameKeyPair> keyPairs =
                new TreeMap<CipherSetIdentifier,HashNameKeyPair>();
        for (Map.Entry<CipherSetIdentifier,HashNamePrivateKey> entry : mPrivateKeys.entrySet()) {
            keyPairs.put(
                    entry.getKey(),
                    Telehash.get().getCrypto().createHashNameKeyPair(
                            mPublicKeys.get(entry.getKey()),
                            entry.getValue()
                    )
            );
        }
        return keyPairs;
    }

    /**
     * Return the hashname private key for the indicated cipher set.
     *
     * @param csid The cipher set id.
     * @return The hashname private key.
     */
    public HashNamePrivateKey getPrivateKey(CipherSetIdentifier csid) {
        return mPrivateKeys.get(csid);
    }
}
