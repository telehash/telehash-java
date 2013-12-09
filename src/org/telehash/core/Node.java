package org.telehash.core;

import org.telehash.crypto.RSAPublicKey;
import org.telehash.network.Endpoint;

/**
 * This class represents a Telehash node, including its public key and network
 * endpoint.
 */
public class Node {
    private RSAPublicKey mPublicKey;
    private Endpoint mEndpoint;
    private HashName mHashName = null;
    private Node mReferringNode;
    
    public Node(RSAPublicKey publicKey, Endpoint endpoint) throws TelehashException {
        mPublicKey = publicKey;
        mEndpoint = endpoint;
        mHashName = new HashName(Util.getCryptoInstance().sha256Digest(mPublicKey.getDEREncoded()));
    }

    public Node(HashName hashName, Endpoint endpoint) throws TelehashException {
        mPublicKey = null;
        mEndpoint = endpoint;
        mHashName = hashName;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        mPublicKey = publicKey;
    }
    
    public RSAPublicKey getPublicKey() {
        return mPublicKey;
    }
    
    public Endpoint getEndpoint() {
        return mEndpoint;
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
        return "Node["+mHashName+"]"+((mPublicKey!=null)?"*":"")+mEndpoint;
    }
}
