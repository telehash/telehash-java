package org.telehash.crypto;

import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.TelehashException;

public interface HashNamePublicKey {
    public CipherSetIdentifier getCipherSetIdentifier();
    public byte[] getEncoded() throws TelehashException;
    public byte[] getFingerprint();
}
