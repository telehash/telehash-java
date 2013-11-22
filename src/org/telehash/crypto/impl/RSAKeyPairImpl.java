package org.telehash.crypto.impl;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.telehash.crypto.RSAKeyPair;
import org.telehash.crypto.RSAPrivateKey;
import org.telehash.crypto.RSAPublicKey;

public class RSAKeyPairImpl implements RSAKeyPair {
    
    private RSAPublicKeyImpl mPublicKey;
    private RSAPrivateKeyImpl mPrivateKey;
    
    public RSAKeyPairImpl(AsymmetricCipherKeyPair keyPair) {
        mPublicKey = new RSAPublicKeyImpl(keyPair.getPublic());
        mPrivateKey = new RSAPrivateKeyImpl(keyPair.getPrivate());
    }
    
    public RSAKeyPairImpl(RSAPublicKeyImpl publicKey, RSAPrivateKeyImpl privateKey) {
        mPublicKey = publicKey;
        mPrivateKey = privateKey;
    }

    @Override
    public RSAPublicKey getPublicKey() {
        return mPublicKey;
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return mPrivateKey;
    }

}
