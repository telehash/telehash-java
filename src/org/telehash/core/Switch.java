package org.telehash.core;

import java.util.Set;

/**
 * The Switch class is the heart of Telehash. The switch is responsible for
 * managing identity and node information, maintaining the DHT, and facilitating
 * inter-node communication.
 */
public class Switch {

    private Identity mIdentity;
    private Set<Node> mSeeds;

    public Switch(String seedsFilename) throws TelehashException {
        mIdentity = Util.getCryptoInstance().generateIdentity();
    }

    public Switch(String identityBaseFilename, String seedsFilename) throws TelehashException {
        mIdentity = Util.getStorageInstance().readIdentity(identityBaseFilename);
    }

    public Switch(Identity identity, Set<Node> seeds) {
        mIdentity = identity;
        mSeeds = seeds;
    }

    public void loop() {
        System.out.println("switch loop with identity="+mIdentity+" and seeds="+mSeeds);
    }
}
