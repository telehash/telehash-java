package org.telehash.core;

import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.Path;

import java.util.Collection;
import java.util.SortedMap;

public class SeedNode extends FullNode {
    public SeedNode(
            FingerprintSet fingerprints,
            SortedMap<CipherSetIdentifier,HashNamePublicKey> publicKeys,
            Collection<Path> paths
    ) {
        super(fingerprints, publicKeys, paths);
    }
}
