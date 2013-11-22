package org.telehash.crypto.impl;

import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.telehash.crypto.ECPrivateKey;

public class ECPrivateKeyImpl implements ECPrivateKey {
    
    private JCEECPrivateKey mKey;
    
    public ECPrivateKeyImpl(JCEECPrivateKey privateKey) {
        mKey = privateKey;
    }

}
