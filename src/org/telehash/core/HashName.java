package org.telehash.core;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Wrap a hash name. This is needed so we can establish a sensible
 * Java object identity and use a hash name as a key in HashMap.
 */
public class HashName {
    public static final int SIZE = 32;

    private byte[] mBuffer;

    public HashName(byte[] buffer) {
        if (buffer == null || buffer.length != SIZE) {
            throw new IllegalArgumentException("invalid hash name");
        }
        mBuffer = buffer;
    }
    
    public BigInteger distance(HashName other) {
        BigInteger a = new BigInteger(1, mBuffer);
        BigInteger b = new BigInteger(1, other.mBuffer);
        return (a.xor(b));
    }
    
    public byte[] getBytes() {
        return mBuffer;
    }
    
    public String asHex() {
        return Util.bytesToHex(mBuffer);
    }
    
    public String toString() {
        return asHex();
    }
    
    // Java identity
    
    @Override
    public boolean equals(Object other) {
        if (other != null &&
            other instanceof HashName &&
            Arrays.equals(((HashName)other).mBuffer, mBuffer)) {
            return true;
        } else {
            return false;
        }
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(mBuffer);
    }

}
