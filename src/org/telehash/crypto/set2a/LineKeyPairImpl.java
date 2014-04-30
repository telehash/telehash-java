package org.telehash.crypto.set2a;

import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.telehash.core.TelehashException;
import org.telehash.crypto.LineKeyPair;
import org.telehash.crypto.LinePrivateKey;
import org.telehash.crypto.LinePublicKey;

public class LineKeyPairImpl implements LineKeyPair {
    LinePublicKeyImpl mPublicKey;
    LinePrivateKeyImpl mPrivateKey;

    public LineKeyPairImpl(
            ECPublicKeyParameters publicKey,
            ECPrivateKeyParameters privateKey
    ) throws TelehashException {
        mPublicKey = new LinePublicKeyImpl(publicKey);
        mPrivateKey = new LinePrivateKeyImpl(privateKey);
    }

    public LineKeyPairImpl(
            LinePublicKey publicKey,
            LinePrivateKey privateKey
    ) throws TelehashException {
        mPublicKey = (LinePublicKeyImpl)publicKey;
        mPrivateKey = (LinePrivateKeyImpl)privateKey;
    }

    @Override
    public LinePrivateKey getPrivateKey() {
        return mPrivateKey;
    }
    @Override
    public LinePublicKey getPublicKey() {
        return mPublicKey;
    }

}
