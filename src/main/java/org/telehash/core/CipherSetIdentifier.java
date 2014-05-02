package org.telehash.core;


/**
 * Wrap a cipher set identifier.
 */
public class CipherSetIdentifier implements Comparable<CipherSetIdentifier> {
    public static final int SIZE = 1;
    private final short mId;

    public CipherSetIdentifier(int id) {
        mId = (short) id;
    }

    public CipherSetIdentifier(short id) {
        mId = id;
    }

    public CipherSetIdentifier(byte id) {
        mId = (short)(id & 0xFF);
    }

    public CipherSetIdentifier(String s) {
        byte[] buffer = Util.hexToBytes(s);
        if (buffer != null && buffer.length == 1) {
            mId = buffer[0];
        } else {
            throw new IllegalArgumentException("bad cipherset id");
        }
    }

    public byte getByte() {
        return (byte) mId;
    }
    public byte[] getBytes() {
        byte[] buffer = new byte[1];
        buffer[0] = (byte)mId;
        return buffer;
    }

    public String asHex() {
        return Util.bytesToHex(getBytes());
    }

    @Override
    public String toString() {
        return asHex();
    }

    // Java identity

    @Override
    public boolean equals(Object other) {
        if (other != null &&
            other instanceof CipherSetIdentifier &&
            ((CipherSetIdentifier)other).mId == mId) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return mId;
    }

    @Override
    public int compareTo(CipherSetIdentifier other) {
        if (other == null) {
            return +1;
        }
        if (this.mId > other.mId) {
            return +1;
        } else if (this.mId < other.mId) {
            return -1;
        } else {
            return 0;
        }
    }

}
