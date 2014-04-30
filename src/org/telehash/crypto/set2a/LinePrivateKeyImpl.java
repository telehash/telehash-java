package org.telehash.crypto.set2a;

import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.LinePrivateKey;

import java.math.BigInteger;

public class LinePrivateKeyImpl implements LinePrivateKey {

    private ECPrivateKeyParameters mKey;

    public LinePrivateKeyImpl(ECPrivateKeyParameters privateKey) {
        mKey = privateKey;
    }

    public LinePrivateKeyImpl(
            byte[] buffer,
            ECDomainParameters domainParameters
    ) throws TelehashException {
        BigInteger d = new BigInteger(Util.bytesToHex(buffer), 16);
        mKey = new ECPrivateKeyParameters(d, domainParameters);
    }

    @Override
    public CipherSetIdentifier getCipherSetIdentifier() {
        return CipherSet2aImpl.CIPHER_SET_ID;
    }

    public ECPrivateKeyParameters getKey() {
        return mKey;
    }

}
