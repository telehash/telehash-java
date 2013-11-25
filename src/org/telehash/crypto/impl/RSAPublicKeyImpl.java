package org.telehash.crypto.impl;

import java.io.IOException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.telehash.core.TelehashException;
import org.telehash.crypto.RSAPublicKey;

public class RSAPublicKeyImpl implements RSAPublicKey {
    
    AsymmetricKeyParameter mKey;
    
    public RSAPublicKeyImpl(AsymmetricKeyParameter key) {
        mKey = key;
    }
    
    public RSAPublicKeyImpl(byte[] derBuffer) throws TelehashException {
        try {
            mKey = PublicKeyFactory.createKey(derBuffer);
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    public AsymmetricKeyParameter getKey() {
        return mKey;
    }
    
    @Override
    public byte[] getDEREncoded() throws TelehashException {
        RSAKeyParameters param = (RSAKeyParameters)mKey;
        org.bouncycastle.asn1.pkcs.RSAPublicKey asn1Key =
                new org.bouncycastle.asn1.pkcs.RSAPublicKey(
                        param.getModulus(), param.getExponent()
                );
        SubjectPublicKeyInfo info;
        try {
            info = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(
                            PKCSObjectIdentifiers.rsaEncryption,
                            null
                    ),
                    asn1Key
            );
        } catch (IOException e) {
            throw new TelehashException(e);
        }
        try {
            return info.getEncoded("DER");
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }
}
