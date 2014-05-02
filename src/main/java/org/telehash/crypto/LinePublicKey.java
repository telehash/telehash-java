package org.telehash.crypto;

import org.telehash.core.CipherSetIdentifier;

public interface LinePublicKey {
    public CipherSetIdentifier getCipherSetIdentifier();
    public byte[] getEncoded();
}
