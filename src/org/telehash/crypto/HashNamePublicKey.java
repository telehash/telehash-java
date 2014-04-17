package org.telehash.crypto;

import org.telehash.core.TelehashException;

public interface HashNamePublicKey {
    public byte[] getEncoded() throws TelehashException;
    public byte[] getFingerprint() throws TelehashException;
}
