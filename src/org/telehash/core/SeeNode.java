package org.telehash.core;

import org.telehash.network.InetPath;
import org.telehash.network.Path;

/**
 * This class represents a Telehash "see" field, containing a hashname,
 * a cipher set identifier, and optionally a path for hole punching.
 */
public class SeeNode extends Node {

    private final CipherSetIdentifier mCipherSetIdentifier;
    private final Path mHolePunchPath;
    private final PeerNode mReferringNode;

    public SeeNode(
            HashName hashName,
            CipherSetIdentifier cipherSetIdentifier,
            Path holePunchPath
    ) {
        super(hashName);
        mCipherSetIdentifier = cipherSetIdentifier;
        mHolePunchPath = holePunchPath;
        mReferringNode = null;
    }

    private SeeNode(
            HashName hashName,
            CipherSetIdentifier cipherSetIdentifier,
            Path holePunchPath,
            PeerNode referringNode
    ) {
        super(hashName);
        mCipherSetIdentifier = cipherSetIdentifier;
        mHolePunchPath = holePunchPath;
        mReferringNode = referringNode;
    }

    public static SeeNode parse(PeerNode referringNode, String seeLine) throws TelehashException {
        String[] parts  = seeLine.split(",");
        if (parts.length != 2 && parts.length != 4) {
            throw new TelehashException("invalid see line: "+seeLine);
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
        return new SeeNode(hashName, cipherSetIdentifier, holePunchPath, referringNode);
    }

    public String render() {
        if (mHolePunchPath == null || (!(mHolePunchPath instanceof InetPath))) {
            return mHashName.asHex() + "," + mCipherSetIdentifier.asHex();
        } else {
            return mHashName.asHex() + "," + mCipherSetIdentifier.asHex() + ","
                    + ((InetPath)mHolePunchPath).getAddress().getHostAddress() + ","
                    + ((InetPath)mHolePunchPath).getPort();
        }
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
        return "SeeNode["+hashName+"/"+mCipherSetIdentifier+"]";
    }
}
