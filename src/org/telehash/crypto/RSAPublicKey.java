package org.telehash.crypto;

import org.telehash.core.TelehashException;

public interface RSAPublicKey {
    public byte[] getDEREncoded() throws TelehashException;
}
