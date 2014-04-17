package org.telehash.crypto;

import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.TelehashException;

public interface HashNamePrivateKey {
    public CipherSetIdentifier getCipherSetIdentifier();
    public byte[] getEncoded() throws TelehashException;
}
