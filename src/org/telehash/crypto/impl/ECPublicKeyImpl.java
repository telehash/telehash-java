package org.telehash.crypto.impl;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.ECPublicKey;

public class ECPublicKeyImpl implements ECPublicKey {
    
    private ECPublicKeyParameters mKey;
    
    public ECPublicKeyImpl(ECPublicKeyParameters publicKey) {
        mKey = publicKey;
    }
 
    public ECPublicKeyImpl(
            byte[] buffer,
            ECDomainParameters domainParameters
    ) throws TelehashException {
        if (buffer.length != 65 || buffer[0] != 0x04) {
            throw new TelehashException("bad ANSI X9.63 EC key encoding");
        }
        byte[] xBytes = new byte[32+1];
        byte[] yBytes = new byte[32+1];
        // assure the leading byte is zero, to indicate a positive value
        xBytes[0] = 0;
        yBytes[0] = 0;
        // copy
        System.arraycopy(buffer, 1, xBytes, 1, 32);
        System.arraycopy(buffer, 1+32, yBytes, 1, 32);
        BigInteger x = new BigInteger(xBytes);
        BigInteger y = new BigInteger(yBytes);
        
        ECPoint q = domainParameters.getCurve().createPoint(x, y, false);
        mKey = new ECPublicKeyParameters(q, domainParameters);
    }
    
    @Override
    public byte[] getEncoded() {
        // return the public key in ANSI X9.63 format
        //mKey.setPointFormat("UNCOMPRESSED");
        ECPoint qPoint = mKey.getQ();

        byte[] xBytes = BigIntegers.asUnsignedByteArray(32, qPoint.getX().toBigInteger());
        byte[] yBytes = BigIntegers.asUnsignedByteArray(32, qPoint.getY().toBigInteger());
        byte[] buffer = new byte[65];
        buffer[0] = 0x04;
        System.arraycopy(xBytes, 0, buffer, 1, xBytes.length);
        System.arraycopy(yBytes, 0, buffer, 1 + xBytes.length, yBytes.length);

        return buffer;
    }
    
    public ECPublicKeyParameters getKey() {
        return mKey;
    }
    
    @Override
    public boolean equals(Object other) {
        if (! (other instanceof ECPublicKey)) {
            return false;
        }
        ECPublicKey otherKey = (ECPublicKey)other;
        return Arrays.equals(this.getEncoded(), otherKey.getEncoded());
    }
}
