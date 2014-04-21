package org.telehash.core;

import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.Path;

import java.util.Collection;
import java.util.NavigableSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

public class PeerNode extends Node {

    private FingerprintSet mFingerprints; // only populate in full
    private final HashNamePublicKey mActivePublicKey; // optional
    private final CipherSetIdentifier mActiveCipherSetIdentifier;
    private SortedSet<Path> mPaths = new TreeSet<Path>();

    protected static class Active {
        public CipherSetIdentifier cipherSetIdentifier;
        public HashNamePublicKey publicKey;
    };

    public PeerNode(HashName hashName, CipherSetIdentifier csid,
            HashNamePublicKey publicKey, Collection<Path> paths) {
        super(hashName);
        mFingerprints = null;
        mActiveCipherSetIdentifier = csid;
        mActivePublicKey = publicKey;
        mPaths.addAll(paths);
    }

    protected PeerNode(
            HashName hashName,
            FingerprintSet fingerprints,
            Active active,
            Collection<Path> paths
    ) {
        super(hashName);
        mFingerprints = fingerprints;
        mActiveCipherSetIdentifier = active.cipherSetIdentifier;
        mActivePublicKey = active.publicKey;
        if (paths != null) {
            mPaths.addAll(paths);
        }
    }

    public PeerNode(HashName hashName, FingerprintSet fingerprints, Collection<Path> paths)
            throws TelehashException {
        super(hashName);
        mFingerprints = fingerprints;
        mActivePublicKey = null;
        mActiveCipherSetIdentifier = null;
        mPaths.addAll(paths);
    }

    public PeerNode(HashName hashName, Collection<Path> paths) throws TelehashException {
        super(hashName);
        mFingerprints = null;
        mActivePublicKey = null;
        mActiveCipherSetIdentifier = null;
        mPaths.addAll(paths);
    }

    public FingerprintSet getFingerprints() {
        return mFingerprints;
    }

    public HashNamePublicKey getActivePublicKey() {
        return mActivePublicKey;
    }

    public CipherSetIdentifier getActiveCipherSetIdentifier() {
        return mActiveCipherSetIdentifier;
    }

    public Set<CipherSetIdentifier> getCipherSetIds() {
        if (mFingerprints != null) {
            return mFingerprints.keySet();
        } else {
            return null;
        }
    }

    @Deprecated
    public Path getPath() {
        return mPaths.first();
    }

    public SortedSet<Path> getPaths() {
        return mPaths;
    }

    public void setPaths(Collection<? extends Path> paths) {
        mPaths.clear();
        mPaths.addAll(paths);
    }

    public void updateFingerprints(FingerprintSet fingerprints) {
        if (mFingerprints == null) {
            mFingerprints = fingerprints;
        } else {
            if (! mFingerprints.equals(fingerprints)) {
                throw new IllegalStateException(
                        "attempt to change the existing fingerprint set of a node."
                );
            }
        }
    }

    public static CipherSetIdentifier bestCipherSet(PeerNode a, PeerNode b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("null peernode provided");
        }
        return FingerprintSet.bestCipherSet(a.mFingerprints, b.mFingerprints);
    }

    protected static CipherSetIdentifier bestCipherSetIdentifier(
            Set<CipherSetIdentifier> theirSet
    ) {
        NavigableSet<CipherSetIdentifier> theirs =
                new TreeSet<CipherSetIdentifier>(theirSet);
        NavigableSet<CipherSetIdentifier> ours =
                Telehash.get().getCrypto().getAllCipherSetsIds();
        for (CipherSetIdentifier csid : ours.descendingSet()) {
            if (theirs.contains(csid)) {
                return csid;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        String hashName = mHashName.getShortHash();
        return "PeerNode["+hashName+"]"+mPaths;
    }
}
