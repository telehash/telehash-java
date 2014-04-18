package org.telehash.core;

import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.Path;

import java.util.Collection;
import java.util.SortedMap;

public abstract class FullNode extends PeerNode {

    // must be fully populated
    protected SortedMap<CipherSetIdentifier,HashNamePublicKey> mPublicKeys;

    protected FullNode(
            SortedMap<CipherSetIdentifier,HashNamePublicKey> publicKeys,
            Collection<Path> paths
    ) {
        super(
                HashName.calculateHashName(publicKeys),
                FingerprintSet.fromPublicKeys(publicKeys),
                determineActiveCipherSetAndKey(publicKeys),
                paths
        );
        mPublicKeys = publicKeys;
    }

    /**
     * Create a new FullNode with the specified fingerprints and public
     * keys. This is useful if we are reading a seeds.json, and thus may
     * need to represent a node with pre-cooked fingerprints that we may
     * not be able to reproduce (if we don't support all the cipher sets
     * of this node!)
     *
     * @param fingerprints
     * @param publicKeys
     * @param paths
     */
    protected FullNode(
            FingerprintSet fingerprints,
            SortedMap<CipherSetIdentifier,HashNamePublicKey> publicKeys,
            Collection<Path> paths
    ) {
        super(
                HashName.calculateHashName(publicKeys),
                FingerprintSet.fromPublicKeys(publicKeys),
                determineActiveCipherSetAndKey(publicKeys),
                paths
        );
        mPublicKeys = publicKeys;
    }

    public SortedMap<CipherSetIdentifier,HashNamePublicKey> getPublicKeys() {
        return mPublicKeys;
    }

    public HashNamePublicKey getPublicKey(CipherSetIdentifier csid) {
        if (mPublicKeys == null) {
            return null;
        }
        return mPublicKeys.get(csid);
    }

    private static Active determineActiveCipherSetAndKey(
            SortedMap<CipherSetIdentifier,HashNamePublicKey> publicKeyMap
    ) {
        Active active = new Active();
        active.cipherSetIdentifier = bestCipherSetIdentifier(publicKeyMap.keySet());
        active.publicKey = publicKeyMap.get(active.cipherSetIdentifier);
        return active;
    }
}
