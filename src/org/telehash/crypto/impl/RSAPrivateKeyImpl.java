package org.telehash.crypto.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.telehash.core.TelehashException;
import org.telehash.crypto.RSAPrivateKey;

public class RSAPrivateKeyImpl implements RSAPrivateKey {

    AsymmetricKeyParameter mKey;
    
    public RSAPrivateKeyImpl(AsymmetricKeyParameter key) {
        mKey = key;
    }
    
    public RSAPrivateKeyImpl(byte[] derBuffer) throws TelehashException {
        try {
            ASN1InputStream asn1InputStream =
                    new ASN1InputStream(new ByteArrayInputStream(derBuffer)); 
            ASN1Primitive toplevelObject = asn1InputStream.readObject(); 
            asn1InputStream.close();
            if (! (toplevelObject instanceof ASN1Sequence)) {
                throw new TelehashException("ASN.1 toplevel object not sequence");
            }
            ASN1Sequence sequence = (ASN1Sequence)toplevelObject;
            if (getIntegerFromSequence(sequence, 0).compareTo(BigInteger.ZERO) != 0) {
                throw new TelehashException("only PKCS#1v1.5 (version=0) structures supported.");
            }
            
            mKey =  new RSAPrivateCrtKeyParameters(
                    getIntegerFromSequence(sequence, 1),
                    getIntegerFromSequence(sequence, 2),
                    getIntegerFromSequence(sequence, 3),
                    getIntegerFromSequence(sequence, 4),
                    getIntegerFromSequence(sequence, 5),
                    getIntegerFromSequence(sequence, 6),
                    getIntegerFromSequence(sequence, 7),
                    getIntegerFromSequence(sequence, 8)
            );
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }
    
    public AsymmetricKeyParameter getKey() {
        return mKey;
    }

    @Override
    public byte[] getDEREncoded() throws TelehashException {
        System.out.println("encoding private key from class: "+mKey.getClass().getName());
        RSAPrivateCrtKeyParameters param = (RSAPrivateCrtKeyParameters)mKey;
        org.bouncycastle.asn1.pkcs.RSAPrivateKey asn1Key;
        asn1Key =
                new org.bouncycastle.asn1.pkcs.RSAPrivateKey(
                    param.getModulus(),
                    param.getPublicExponent(),
                    param.getExponent(),
                    param.getP(),
                    param.getQ(),
                    param.getDP(),
                    param.getDQ(),
                    param.getQInv()
                );

        // dump
        /*
        try {
            ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(asn1Key.getEncoded("DER")));
            ASN1Primitive obj = in.readObject();
            System.out.println("---- RSAPrivateKeyImpl dump:");
            System.out.println(ASN1Dump.dumpAsString(obj));
            System.out.println("----");
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        */
        
        try {
            return asn1Key.getEncoded("DER");
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Helper method to extract a BigInteger from an ASN1 sequence.
     * 
     * @param sequence An ASN1 sequence
     * @param index The index of the sequence from which we fetch the ASN1Integer value.
     * @return The integer value.
     * @throws TelehashException
     */
    private BigInteger getIntegerFromSequence(
            ASN1Sequence sequence,
            int index
    ) throws TelehashException {
        ASN1Encodable encodable = sequence.getObjectAt(index);
        if (!(encodable instanceof ASN1Integer)) {
            throw new TelehashException("error parsing ASN.1: expected integer");
        }
        return ((ASN1Integer)encodable).getValue();
    }
}
