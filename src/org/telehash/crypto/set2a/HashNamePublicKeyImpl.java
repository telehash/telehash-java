package org.telehash.crypto.set2a;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.Log;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.HashNamePublicKey;

import java.io.IOException;
import java.math.BigInteger;

public class HashNamePublicKeyImpl implements HashNamePublicKey {

    static private final int PKCS1V21_MODULUS_INDEX = 0;
    static private final int PKCS1V21_EXPONENT_INDEX = 1;

    /**
     * When encoding, should we use PKCS#1 v2.1 or X.509 SPKI?
     */
    static private final boolean USE_PKCS1V21 = false;

    private AsymmetricKeyParameter mKey;

    public HashNamePublicKeyImpl(AsymmetricKeyParameter key) {
        mKey = key;
    }

    public HashNamePublicKeyImpl(byte[] derBuffer) throws TelehashException {

        // first attempt to parse the buffer as a PKCS#1 v2.1 ASN.1 structure
        // (see: RFC 3447 section A.1.1)
        try {
            ASN1Primitive asn1 = ASN1Primitive.fromByteArray(derBuffer);
            if (asn1 instanceof ASN1Sequence) {
                ASN1Sequence sequence = (ASN1Sequence)asn1;
                ASN1Primitive modulusPrim =
                        sequence.getObjectAt(PKCS1V21_MODULUS_INDEX).toASN1Primitive();
                ASN1Primitive exponentPrim =
                        sequence.getObjectAt(PKCS1V21_EXPONENT_INDEX).toASN1Primitive();
                if (modulusPrim instanceof ASN1Integer && exponentPrim instanceof ASN1Integer) {
                    BigInteger modulus = ((ASN1Integer)modulusPrim).getPositiveValue();
                    BigInteger exponent = ((ASN1Integer)exponentPrim).getPositiveValue();
                    mKey = new RSAKeyParameters(false, modulus, exponent);
                    return;
                }
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            // fallback to SPKI parsing
        } catch (IOException e) {
            // fallback to SPKI parsing
        }

        // parse the buffer, assuming an X.509 SubjectPublicKeyInfo ASN.1 structure
        try {
            mKey = PublicKeyFactory.createKey(derBuffer);
        } catch (IOException e) {
            Util.hexdump(derBuffer);
            throw new TelehashException(e);
        }
    }

    public AsymmetricKeyParameter getKey() {
        return mKey;
    }

    @Override
    public CipherSetIdentifier getCipherSetIdentifier() {
        return CipherSet2aImpl.CIPHER_SET_ID;
    }

    /**
     * Encode the public key as a DER representation.
     */
    @Override
    public byte[] getEncoded() throws TelehashException {
        if (USE_PKCS1V21) {
            return getPKCS1V21Encoded();
        } else {
            return getSPKIEncoded();
        }
    }

    /**
     * Render the public key in PKCS#1 v2.1 ASN.1 format.
     * (see: RFC 3447 section A.1.1)
     *
     * @throws TelehashException
     */
    public byte[] getPKCS1V21Encoded() throws TelehashException {
        if (! (mKey instanceof RSAKeyParameters)) {
            throw new TelehashException("key is not RSA");
        }
        RSAKeyParameters rsaPublicKey = (RSAKeyParameters)mKey;
        ASN1EncodableVector  v = new ASN1EncodableVector();
        v.add(new ASN1Integer(rsaPublicKey.getModulus()));
        v.add(new ASN1Integer(rsaPublicKey.getExponent()));
        ASN1Sequence sequence = new DERSequence(v);
        try {
            return sequence.getEncoded();
        } catch (IOException e) {
            throw new TelehashException("cannot encode key", e);
        }
    }

    /**
     * Render the public key in X.509 SPKI ASN.1 format.
     *
     * @throws TelehashException
     */
    public byte[] getSPKIEncoded() throws TelehashException {
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

    @Override
    public byte[] getFingerprint() {
        try {
            return Telehash.get().getCrypto().sha256Digest(getEncoded());
        } catch (TelehashException e) {
            Log.e("sha256 failure", e);
            return null;
        }
    }
}
