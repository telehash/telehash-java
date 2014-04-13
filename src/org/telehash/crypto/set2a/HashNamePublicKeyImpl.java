package org.telehash.crypto.set2a;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.telehash.core.TelehashException;
import org.telehash.crypto.HashNamePublicKey;

import java.io.IOException;

public class HashNamePublicKeyImpl implements HashNamePublicKey {

    AsymmetricKeyParameter mKey;

    public HashNamePublicKeyImpl(AsymmetricKeyParameter key) {
        mKey = key;
    }

    public HashNamePublicKeyImpl(byte[] derBuffer) throws TelehashException {
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
    public byte[] getEncoded() throws TelehashException {
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
