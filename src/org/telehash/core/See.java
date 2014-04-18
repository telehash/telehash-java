package org.telehash.core;

import org.telehash.network.Path;

/**
 * This class represents a Telehash "see" field, containing a hashname,
 * a cipher set identifier, and optionally a path for hole punching.
 */
public class See extends Node {

    private final CipherSetIdentifier mCipherSetIdentifier;
    private final Path mHolePunchPath;
    private final PeerNode mReferringNode;

    private See(HashName hashName, CipherSetIdentifier cipherSetIdentifier, Path holePunchPath) {
        super(hashName);
        mCipherSetIdentifier = cipherSetIdentifier;
        mHolePunchPath = holePunchPath;
        // TODO: referring node should NEVER be null!
        mReferringNode = null;
    }

    public static See parse(Node referringNode, String seeLine) throws TelehashException {
        String[] parts  = seeLine.split(",");
        if (parts.length != 2 && parts.length != 4) {
            throw new TelehashException("invalid see line");
        }

        HashName hashName = new HashName(Util.hexToBytes(parts[0]));
        CipherSetIdentifier cipherSetIdentifier = new CipherSetIdentifier(parts[1]);
        Path holePunchPath;
        if (parts.length == 4) {
            try {
                holePunchPath =
                        Telehash.get().getNetwork().parsePath(parts[2], Integer.parseInt(parts[3]));
            } catch (NumberFormatException e) {
                throw new TelehashException(e);
            }
        } else {
            holePunchPath = null;
        }
        return new See(hashName, cipherSetIdentifier, holePunchPath);
    }

    public CipherSetIdentifier getCipherSetIdentifier() {
        return mCipherSetIdentifier;
    }

    public Path getHolePunchPath() {
        return mHolePunchPath;
    }

    public PeerNode getReferringNode() {
        return mReferringNode;
    }

    @Override
    public String toString() {
        String hashName = mHashName.toString().substring(0, 8);
        return "See["+hashName+"/"+mCipherSetIdentifier+"]";
    }
}
