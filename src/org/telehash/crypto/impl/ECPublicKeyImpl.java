package org.telehash.crypto.impl;

import java.math.BigInteger;

import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.telehash.core.TelehashException;
import org.telehash.crypto.ECPublicKey;

public class ECPublicKeyImpl implements ECPublicKey {
    
    private JCEECPublicKey mKey;
    
    public ECPublicKeyImpl(JCEECPublicKey publicKey) {
        mKey = publicKey;
    }
    
    public ECPublicKeyImpl(byte[] buffer) throws TelehashException {
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
        System.arraycopy(buffer, 1, yBytes, 1+32, 32);
        BigInteger x = new BigInteger(xBytes);
        BigInteger y = new BigInteger(yBytes);
        
//        mKey = new JCEECPublicKey("ECDH", 3);
        
    }
    
    public byte[] getUncompressedKey() {
        // return the public key in ANSI X9.63 format
        mKey.setPointFormat("UNCOMPRESSED");
        ECPoint qPoint = mKey.getQ();

        // TODO: update bouncy castle, then specify length=64.
        byte[] xBytes = BigIntegers.asUnsignedByteArray(qPoint.getX().toBigInteger());
        byte[] yBytes = BigIntegers.asUnsignedByteArray(qPoint.getY().toBigInteger());
        byte[] buffer = new byte[65];
        buffer[0] = 0x04;
        System.arraycopy(xBytes, 0, buffer, 1, xBytes.length);
        System.arraycopy(yBytes, 0, buffer, 1 + xBytes.length, yBytes.length);

        return buffer;
    }
}
