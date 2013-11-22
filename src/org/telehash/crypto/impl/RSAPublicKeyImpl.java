package org.telehash.crypto.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
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
        ASN1Primitive obj;
        ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(derBuffer));
        try {
            obj = bIn.readObject();
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        }
        System.out.println("RSAPublicKeyImpl dump:");
        System.out.println(ASN1Dump.dumpAsString(obj));
        
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
