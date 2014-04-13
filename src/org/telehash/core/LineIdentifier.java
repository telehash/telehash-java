package org.telehash.core;

import java.util.Arrays;

/**
 * Wrap a binary line identifier. This is needed so we can establish a sensible
 * Java object identity and use a line identifier as a key in HashMap.
 */
public class LineIdentifier {
    public static final int LINE_IDENTIFIER_SIZE = 16;

    private byte[] mBuffer;

    public LineIdentifier(byte[] buffer) {
        if (buffer == null || buffer.length != LINE_IDENTIFIER_SIZE) {
            throw new IllegalArgumentException("invalid line id");
        }
        mBuffer = buffer;
    }

    public byte[] getBytes() {
        return mBuffer;
    }

    public String asHex() {
        return Util.bytesToHex(mBuffer);
    }

    @Override
    public String toString() {
        return asHex();
    }

    // Java identity

    @Override
    public boolean equals(Object other) {
        if (other != null &&
            other instanceof LineIdentifier &&
            Arrays.equals(((LineIdentifier)other).mBuffer, mBuffer)) {
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
