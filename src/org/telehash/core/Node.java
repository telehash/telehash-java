package org.telehash.core;

import org.telehash.crypto.RSAPublicKey;
import org.telehash.network.Path;

/**
 * This class represents a Telehash node, including its public key and network
 * path.
 */
public class Node {
    private RSAPublicKey mPublicKey;
    private Path mPath;
    private HashName mHashName = null;
    private Node mReferringNode;
    
    public Node(RSAPublicKey publicKey, Path path) throws TelehashException {
        mPublicKey = publicKey;
        mPath = path;
        mHashName = new HashName(
                Telehash.get().getCrypto().sha256Digest(mPublicKey.getDEREncoded())
        );
    }

    public Node(HashName hashName, Path path) throws TelehashException {
        mPublicKey = null;
        mPath = path;
        mHashName = hashName;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        mPublicKey = publicKey;
    }
    
    public RSAPublicKey getPublicKey() {
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
