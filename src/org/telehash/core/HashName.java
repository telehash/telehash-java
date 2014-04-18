package org.telehash.core;

import org.telehash.crypto.HashNamePublicKey;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

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

    /**
     * Return the hashspace distance magnitude between this hashname and the
     * specified hashname. This is defined as the binary logarithm of the xor of
     * the two hashnames (or -1, if the hashnames are identical). This
     * distance magnitude metric is suitable for use as an index into an array
     * of buckets. (Unless the returned value is -1 indicating the hashnames are
     * the same, in which case nothing should be stored in a bucket.)
     *
     * The returned value will always be between -1 and 255, inclusive.
     *
     * @param A
     *            The first hashname.
     * @param other
     *            The second hashname.
     * @return The distance, or -1 if the hashnames are identical.
     */
    public int distanceMagnitude(HashName other) {
        // opportunities for optimization abound.
        // http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious

        if (this == null || other == null) {
            throw new IllegalArgumentException("invalid hashname");
        }
        byte[] ba = this.getBytes();
        byte[] bb = other.getBytes();
        for (int i=0; i<HashName.SIZE; i++) {
            int c = ba[i] ^ bb[i];
            if (c != 0) {
                for (int j=0; j<8; j++) {
                    if ((c & 0x80) != 0) {
                        return (HashName.SIZE-i-1)*8 + (8-j-1);
                    }
                    c = c << 1;
                }
            }
        }
        return -1;
    }

    public byte[] getBytes() {
        return mBuffer;
    }

    public String asHex() {
        return Util.bytesToHex(mBuffer);
    }

    public static HashName calculateHashName(
            SortedMap<CipherSetIdentifier,HashNamePublicKey> publicKeys
    ) {
        // compose the hash name
        SortedMap<CipherSetIdentifier,byte[]> fingerprintMap =
                new TreeMap<CipherSetIdentifier,byte[]>();
        for (Map.Entry<CipherSetIdentifier,HashNamePublicKey> entry : publicKeys.entrySet()) {
            fingerprintMap.put(entry.getKey(), entry.getValue().getFingerprint());
        }
        FingerprintSet fingerprints = new FingerprintSet(fingerprintMap);
        return fingerprints.getHashName();
    }

    @Override
    public String toString() {
        return asHex();
    }

    public String getShortHash() {
        return toString().substring(0, 8);
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
