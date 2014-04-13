package org.telehash.core;

import java.util.Arrays;

/**
 * Wrap a binary channel identifier. This is needed so we can establish a
 * sensible Java object identity and use a channel identifier as a key in
 * HashMap.
 */
public class ChannelIdentifier {
    public static final int CHANNEL_IDENTIFIER_SIZE = 16;

    private byte[] mBuffer;

    public ChannelIdentifier(byte[] buffer) {
        if (buffer == null || buffer.length != CHANNEL_IDENTIFIER_SIZE) {
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
            other instanceof ChannelIdentifier &&
            Arrays.equals(((ChannelIdentifier)other).mBuffer, mBuffer)) {
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
