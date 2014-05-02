package org.telehash.crypto.set2a;

import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;

public class HashNameKeyPairImpl implements HashNameKeyPair {

    private HashNamePublicKeyImpl mPublicKey;
    private HashNamePrivateKeyImpl mPrivateKey;

    public HashNameKeyPairImpl(HashNamePublicKeyImpl publicKey, HashNamePrivateKeyImpl privateKey) {
        mPublicKey = publicKey;
        mPrivateKey = privateKey;
    }

    @Override
    public HashNamePublicKey getPublicKey() {
        return mPublicKey;
    }

    @Override
    public HashNamePrivateKey getPrivateKey() {
        return mPrivateKey;
    }

}
