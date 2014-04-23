package org.telehash.core;


/**
 * Wrap a binary channel identifier. This is needed so we can establish a
 * sensible Java object identity and use a channel identifier as a key in
 * HashMap.
 */
public class ChannelIdentifier {
    public static final long MAX_CHANNEL_ID = (1L<<32)-1;

    private long mId;

    public ChannelIdentifier(long id) {
        if (id <= 0 || id > MAX_CHANNEL_ID) {
            throw new IllegalArgumentException("invalid line id");
        }
        mId = id;
    }

    public ChannelIdentifier(String s) {
        mId = Long.parseLong(s);
        if (mId <= 0 || mId > MAX_CHANNEL_ID) {
            throw new IllegalArgumentException("invalid line id");
        }
    }

    @Override
    public String toString() {
        return Long.toString(mId);
    }

    // Java identity

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (mId ^ (mId >>> 32));
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ChannelIdentifier other = (ChannelIdentifier) obj;
        if (mId != other.mId)
            return false;
        return true;
    }
}
