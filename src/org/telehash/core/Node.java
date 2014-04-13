package org.telehash.core;

import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.Path;

/**
 * This class represents a Telehash node, including its public key and network
 * path.
 *
 * TODO: A node can have multiple network paths.
 */
public class Node {
    private HashNamePublicKey mPublicKey;
    // TODO: support multiple paths per node.
    private Path mPath;
    private HashName mHashName = null;
    private Node mReferringNode;

    public Node(HashNamePublicKey publicKey, Path path) throws TelehashException {
        mPublicKey = publicKey;
        mPath = path;
        mHashName = new HashName(
                Telehash.get().getCrypto().sha256Digest(mPublicKey.getEncoded())
        );
    }

    public Node(HashName hashName, Path path) throws TelehashException {
        mPublicKey = null;
        mPath = path;
        mHashName = hashName;
    }

    public void setPublicKey(HashNamePublicKey publicKey) {
        mPublicKey = publicKey;
    }

    public HashNamePublicKey getPublicKey() {
        return mPublicKey;
    }

    public Path getPath() {
        return mPath;
    }

    public HashName getHashName() {
        return mHashName;
    }

    public void setReferringNode(Node referringNode) {
        mReferringNode = referringNode;
    }

    public Node getReferringNode() {
        return mReferringNode;
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
        return "Node["+hashName+"]"+((mPublicKey!=null)?"*":"")+mPath;
    }
}
