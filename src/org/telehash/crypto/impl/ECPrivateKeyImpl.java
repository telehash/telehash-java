package org.telehash.crypto.impl;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.telehash.crypto.ECPrivateKey;

public class ECPrivateKeyImpl implements ECPrivateKey {
    
    private ECPrivateKeyParameters mKey;
    
    public ECPrivateKeyImpl(ECPrivateKeyParameters privateKey) {
        mKey = privateKey;
    }

    /*
    public ECPrivateKeyImpl(byte[] buffer) {
        // TODO Auto-generated constructor stub
    }
    */
    
    public ECPrivateKeyParameters getKey() {
        return mKey;
    }

}
