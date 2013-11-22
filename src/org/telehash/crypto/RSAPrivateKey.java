package org.telehash.crypto;

import org.telehash.core.TelehashException;

public interface RSAPrivateKey {
    public byte[] getDEREncoded() throws TelehashException;
}
