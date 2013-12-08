package org.telehash.core;

import java.util.Arrays;

import org.telehash.crypto.RSAPublicKey;
import org.telehash.network.Endpoint;

/**
 * This class represents a Telehash node, including its public key and network
 * endpoint.
 */
public class Node {
    public static final int HASHNAME_SIZE = 32;
    
    private RSAPublicKey mPublicKey;
    private Endpoint mEndpoint;
    private byte[] mHashName = null;
    
    public Node(RSAPublicKey publicKey, Endpoint endpoint) throws TelehashException {
        mPublicKey = publicKey;
        mEndpoint = endpoint;
        mHashName = Util.getCryptoInstance().sha256Digest(mPublicKey.getDEREncoded());
    }

    public Node(byte[] hashName, Endpoint endpoint) throws TelehashException {
        mPublicKey = null;
        mEndpoint = endpoint;
        mHashName = hashName;
    }

    public RSAPublicKey getPublicKey() {
        return mPublicKey;
    }
    
    public Endpoint getEndpoint() {
        return mEndpoint;
    }
    
    public byte[] getHashName() {
        return mHashName;
    }
    
    // Java identity
    
    @Override
    public boolean equals(Object other) {
        if (other instanceof Node && Arrays.equals(((Node)other).getHashName(), getHashName())) {
            return true;
        } else {
            return false;
        }
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(getHashName());
    }
}
