package org.telehash.crypto.impl;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.ECPrivateKey;

public class ECPrivateKeyImpl implements ECPrivateKey {
    
    private ECPrivateKeyParameters mKey;
    
    public ECPrivateKeyImpl(ECPrivateKeyParameters privateKey) {
        mKey = privateKey;
    }
    
    public ECPrivateKeyImpl(
            byte[] buffer,
            ECDomainParameters domainParameters
    ) throws TelehashException {
        BigInteger d = new BigInteger(Util.bytesToHex(buffer), 16);
        mKey = new ECPrivateKeyParameters(d, domainParameters);
    }

    public ECPrivateKeyParameters getKey() {
        return mKey;
    }

}
