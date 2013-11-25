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
    
    // TODO: java identity
    
    public Node(RSAPublicKey publicKey, Endpoint endpoint) {
        mPublicKey = publicKey;
        mEndpoint = endpoint;
    }

    public RSAPublicKey getPublicKey() {
        return mPublicKey;
    }
    
    public Endpoint getEndpoint() {
        return mEndpoint;
    }
    
    public byte[] getHashName() throws TelehashException {
        return Util.getCryptoInstance().sha256Digest(mPublicKey.getDEREncoded());
    }
}
