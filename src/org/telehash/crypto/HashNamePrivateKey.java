package org.telehash.crypto;

import org.telehash.core.TelehashException;

public interface HashNamePrivateKey {
    public byte[] getEncoded() throws TelehashException;
}
