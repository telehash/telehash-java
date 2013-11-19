package org.telehash.core;

import java.security.PublicKey;

import org.telehash.network.Endpoint;

/**
 * This class represents a Telehash node, including its public key and network
 * endpoint.
 */
public class Node {
    private PublicKey mPublicKey;
    private Endpoint mEndpoint;
    
    // TODO: java identity
    
    public Node(PublicKey publicKey, Endpoint endpoint) {
        mPublicKey = publicKey;
        mEndpoint = endpoint;
    }

    public PublicKey getPublicKey() {
        return mPublicKey;
    }
    
    public Endpoint getEndpoint() {
        return mEndpoint;
    }
}
