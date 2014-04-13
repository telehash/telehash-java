package org.telehash.crypto.set2a;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.telehash.core.TelehashException;
import org.telehash.crypto.LinePublicKey;

public class LinePublicKeyImpl implements LinePublicKey {
    
    private ECPublicKeyParameters mKey;
    
    public LinePublicKeyImpl(ECPublicKeyParameters publicKey) {
        mKey = publicKey;
    }
 
    public LinePublicKeyImpl(
            byte[] buffer,
            ECDomainParameters domainParameters
    ) throws TelehashException {
        // expect the public key in ANSI X9.63 format,
        // with the "04" identifier prefix byte removed
        if (buffer.length != 64) {
            throw new TelehashException("bad ANSI X9.63 (sans prefix) EC key encoding");
        }
        byte[] xBytes = new byte[32+1];
        byte[] yBytes = new byte[32+1];
        // assure the leading byte is zero, to indicate a positive value
        xBytes[0] = 0;
        yBytes[0] = 0;
        // copy
        System.arraycopy(buffer, 0, xBytes, 1, 32);
        System.arraycopy(buffer, 32, yBytes, 1, 32);
        BigInteger x = new BigInteger(xBytes);
        BigInteger y = new BigInteger(yBytes);
        
        ECPoint q = domainParameters.getCurve().createPoint(x, y, false);
        mKey = new ECPublicKeyParameters(q, domainParameters);
    }
    
    @Override
    public byte[] getEncoded() {
        // return the public key in ANSI X9.63 format,
        // with the "04" identifier prefix byte removed
        ECPoint qPoint = mKey.getQ();

        byte[] xBytes = BigIntegers.asUnsignedByteArray(32, qPoint.getX().toBigInteger());
        byte[] yBytes = BigIntegers.asUnsignedByteArray(32, qPoint.getY().toBigInteger());
        byte[] buffer = new byte[64];
        System.arraycopy(xBytes, 0, buffer, 0, xBytes.length);
        System.arraycopy(yBytes, 0, buffer, xBytes.length, yBytes.length);

        return buffer;
    }
    
    public ECPublicKeyParameters getKey() {
        return mKey;
    }
    
    @Override
    public boolean equals(Object other) {
        if (! (other instanceof LinePublicKey)) {
            return false;
        }
        LinePublicKey otherKey = (LinePublicKey)other;
        return Arrays.equals(this.getEncoded(), otherKey.getEncoded());
    }
}
