package org.telehash.crypto.impl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.telehash.core.TelehashException;
import org.telehash.crypto.ECKeyPair;
import org.telehash.crypto.ECPrivateKey;
import org.telehash.crypto.ECPublicKey;

public class ECKeyPairImpl implements ECKeyPair {
    ECPrivateKeyImpl mPrivateKey;
    ECPublicKeyImpl mPublicKey;
    
    public ECKeyPairImpl(KeyPair keyPair) throws TelehashException {
        PrivateKey privateKey = keyPair.getPrivate();
        if (! (privateKey instanceof JCEECPrivateKey)) {
            throw new TelehashException(
                "EC private key not JCEECPrivateKey."
            );
        }
        mPrivateKey = new ECPrivateKeyImpl((JCEECPrivateKey)privateKey);
        
        PublicKey publicKey = keyPair.getPublic();
        if (! (publicKey instanceof JCEECPublicKey)) {
            throw new TelehashException(
                "EC public key not JCEECPublicKey."
            );
        }
        mPublicKey = new ECPublicKeyImpl((JCEECPublicKey)publicKey);
    }
    
    public ECPrivateKey getPrivateKey() {
        return mPrivateKey;
    }
    public ECPublicKey getPublicKey() {
        return mPublicKey;
    }

}
