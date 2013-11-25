package org.telehash.crypto.impl;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.telehash.core.TelehashException;
import org.telehash.crypto.ECKeyPair;
import org.telehash.crypto.ECPrivateKey;
import org.telehash.crypto.ECPublicKey;

public class ECKeyPairImpl implements ECKeyPair {
    ECPublicKeyImpl mPublicKey;
    ECPrivateKeyImpl mPrivateKey;
    
    public ECKeyPairImpl(
            ECPublicKeyParameters publicKey,
            ECPrivateKeyParameters privateKey
    ) throws TelehashException {
        mPublicKey = new ECPublicKeyImpl(publicKey);
        mPrivateKey = new ECPrivateKeyImpl(privateKey);
    }
    
    public ECPrivateKey getPrivateKey() {
        return mPrivateKey;
    }
    public ECPublicKey getPublicKey() {
        return mPublicKey;
    }

}
