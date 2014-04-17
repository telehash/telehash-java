package org.telehash.core;

import org.telehash.network.Path;

/**
 * This class represents a Telehash "see" field, containing a hashname,
 * a cipher set identifier, and optionally a path for hole punching.
 */
public class See {

    private final HashName mHashName;
    private final CipherSetIdentifier mCipherSetIdentifier;
    private final Path mPath;

    public See(HashName hashName, CipherSetIdentifier cipherSetIdentifier, Path path) {
        mHashName = hashName;
        mCipherSetIdentifier = cipherSetIdentifier;
        mPath = path;
    }

    public HashName getHashName() {
        return mHashName;
    }

    public CipherSetIdentifier getCipherSetIdentifier() {
        return mCipherSetIdentifier;
    }

    public Path getPath() {
        return mPath;
    }

    // Java identity

    @Override
    public boolean equals(Object other) {
        if (    other != null &&
                other instanceof See &&
                ((See)other).getHashName().equals(mHashName)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return mHashName.hashCode();
    }

    @Override
    public String toString() {
        String hashName = mHashName.toString().substring(0, 8);
        return "See["+hashName+"/"+mCipherSetIdentifier+"]";
    }
}
