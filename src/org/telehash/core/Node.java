package org.telehash.core;

import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.Path;

import java.util.Map;
import java.util.TreeMap;

/**
 * This class represents a Telehash node, including its public keys,
 * fingerprints, and network paths.
 *
 * <p>
 * The data associated with a node varies throughout the Telehash protocol and
 * the operation of the switch, due to various steps having incomplete
 * information about the possible fields: private keys, public keys,
 * fingerprints, hashname, supported cipher sets, and network paths. This
 * information may be represented by objects of various classes:
 * </p>
 *
 * <ol>
 * <li>A switch owns an Identity object which contains the key pairs for all
 * cipher sets, from which its fingerprints, hashname, and supported cipher sets
 * may be derived. A switch may have partial knowledge of its network paths as
 * obtained by enumerating the local network interfaces, which may be augmented
 * later if a different public network path (e.g. at a NAT router) is
 * discovered.</li>
 * <li>A Node object contains general information about Telehash nodes,
 * including:
 * <ul>
 * <li>A mandatory hashname field.</li>
 * <li>An optional map of fingerprints. If present, this field must be fully
 * populated for all cipher sets supported by the node.</li>
 * <li>An optional map of public keys, at most one per cipher set. This map may
 * be only partially populated -- for example, we'll usually only have a single
 * public key for any given remote node, unless we read its full set of keys
 * from a seeds.json file.</li>
 * <li>An optional set of network paths by which this node may be reached.</li>
 * <li>A reference to the referring node which is available to introduce us to
 * this node.</li>
 * </ul>
 * </li>
 * <li>A See object contains a hashname, a cipher set identifier, and optionally
 * a path for hole punching.</li>
 * </ol>
 *
 * <p>
 * A Node object may be degenerated from an Identity object, and a See object
 * may be degenerated from a Node object. Likewise, the identification data may
 * be degenerated in a similar manner: A set of key pairs for a node may yield a
 * set of only public keys, which may yield the set of fingerprints, which may
 * yield the hashname.
 * </p>
 */
public class Node {

    private final HashName mHashName;
    private FingerprintSet mFingerprints = null; // only populate in full
    private Map<CipherSetIdentifier,HashNamePublicKey> mPublicKeys =
            new TreeMap<CipherSetIdentifier,HashNamePublicKey>(); // may be partially populated
    // TODO: support multiple paths per node.
    private Path mPath;
    private Node mReferringNode;

    public Node(HashName hashName, CipherSetIdentifier csid,
            HashNamePublicKey publicKey, Path path) {
        mHashName = hashName;
        mFingerprints = null;
        mPublicKeys.put(csid, publicKey);
        mPath = path;
    }

    public Node(Map<CipherSetIdentifier, HashNamePublicKey> publicKeys, Path path)
            throws TelehashException {
        mHashName = HashName.calculateHashName(publicKeys);

        Map<CipherSetIdentifier,byte[]> fingerprints = new TreeMap<CipherSetIdentifier, byte[]>();
        for (Map.Entry<CipherSetIdentifier, HashNamePublicKey> entry : publicKeys.entrySet()) {
            fingerprints.put(entry.getKey(), entry.getValue().getFingerprint());
        }
        mFingerprints = new FingerprintSet(fingerprints);

        mPublicKeys.putAll(publicKeys);
        mPath = path;
        validate();
    }

    public Node(HashName hashName, FingerprintSet fingerprints, Path path)
            throws TelehashException {
        mHashName = hashName;
        mFingerprints = fingerprints;
        mPath = path;
        validate();
    }

    public Node(HashName hashName, Path path) throws TelehashException {
        mHashName = hashName;
        mFingerprints = null;
        mPath = path;
    }

    @Deprecated
    public Node(HashNamePublicKey publicKey, Path path) throws TelehashException {
        mPublicKeys.put(Telehash.get().getCrypto().getCipherSet().getCipherSetId(), publicKey);
        mHashName = HashName.calculateHashName(mPublicKeys);
        Map<CipherSetIdentifier,byte[]> fingerprints = new TreeMap<CipherSetIdentifier,byte[]>();
        fingerprints.put(
                Telehash.get().getCrypto().getCipherSet()
                .getCipherSetId(), publicKey.getFingerprint()
        );
        mFingerprints = new FingerprintSet(fingerprints);
        mPath = path;
        validate();
    }

    public HashName getHashName() {
        return mHashName;
    }

    public FingerprintSet getFingerprints() {
        return mFingerprints;
    }

    public HashNamePublicKey getPublicKey(CipherSetIdentifier csid) {
        if (mPublicKeys == null) {
            return null;
        }
        return mPublicKeys.get(csid);
    }

    public Path getPath() {
        return mPath;
    }

    public void setReferringNode(Node referringNode) {
        mReferringNode = referringNode;
    }

    public Node getReferringNode() {
        return mReferringNode;
    }

    public boolean hasPublicKey() {
        if (mPublicKeys.isEmpty()) {
            return false;
        } else {
            return true;
        }
    }

    public void update(Node other) {
        if (! other.mHashName.equals(mHashName)) {
            throw new IllegalStateException("attempt to update node with other hashname");
        }

        if (mFingerprints == null && other.mFingerprints != null) {
            mFingerprints = other.mFingerprints;
        }

        for (Map.Entry<CipherSetIdentifier, HashNamePublicKey> entry :
                other.mPublicKeys.entrySet()) {
            if (! mPublicKeys.containsKey(entry.getKey())) {
                mPublicKeys.put(entry.getKey(), entry.getValue());
            }
        }
    }

    public void updatePublicKey(CipherSetIdentifier csid, HashNamePublicKey publicKey) {
        if (! mPublicKeys.containsKey(csid)) {
            mPublicKeys.put(csid, publicKey);
        }
    }

    public void updateFingerprints(FingerprintSet fingerprints) {
        if (mFingerprints == null) {
            mFingerprints = fingerprints;
            validate();
        } else {
            if (! mFingerprints.equals(fingerprints)) {
                throw new IllegalStateException(
                        "attempt to change the existing fingerprint set of a node."
                );
            }
        }
    }

    public static CipherSetIdentifier bestCipherSet(Node a, Node b) {
        CipherSetIdentifier bestCipherSetIdentifier = null;
        return FingerprintSet.bestCipherSet(a.mFingerprints, b.mFingerprints);
    }

    private void validate() {
        if (mFingerprints != null) {
            for (CipherSetIdentifier csid : mPublicKeys.keySet()) {
                if (! mFingerprints.containsKey(csid)) {
                    throw new IllegalStateException(
                            "node has public key of a cipher set it doesn't support.");
                }
            }
        }
    }

    // Java identity

    @Override
    public boolean equals(Object other) {
        if (    other != null &&
                other instanceof Node &&
                ((Node)other).getHashName().equals(mHashName)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return mHashName.hashCode();
    }

    @Override
    public String toString() {
        String hashName = mHashName.toString().substring(0, 8);
        return "Node["+hashName+"]"+((mPublicKeys!=null)?"*":"")+mPath;
    }
}
