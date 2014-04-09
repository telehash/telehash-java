package org.telehash.crypto.set2a;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.LinePrivateKey;

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

    public ECPrivateKeyParameters getKey() {
        return mKey;
    }

}
