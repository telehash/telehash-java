package org.telehash.crypto.set2a;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.telehash.core.TelehashException;
import org.telehash.crypto.HashNamePrivateKey;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class HashNamePrivateKeyImpl implements HashNamePrivateKey {

    RSAPrivateCrtKeyParameters mKey;

    public HashNamePrivateKeyImpl(RSAPrivateCrtKeyParameters key) {
        mKey = key;
    }

    public HashNamePrivateKeyImpl(byte[] derBuffer) throws TelehashException {
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

            mKey = new RSAPrivateCrtKeyParameters(
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
    public byte[] getEncoded() throws TelehashException {
        org.bouncycastle.asn1.pkcs.RSAPrivateKey asn1Key;
        asn1Key =
                new org.bouncycastle.asn1.pkcs.RSAPrivateKey(
                    mKey.getModulus(),
                    mKey.getPublicExponent(),
                    mKey.getExponent(),
                    mKey.getP(),
                    mKey.getQ(),
                    mKey.getDP(),
                    mKey.getDQ(),
                    mKey.getQInv()
                );

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
