package org.telehash.sample;

import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.LocalNode;
import org.telehash.core.SeedNode;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.storage.Storage;
import org.telehash.storage.impl.StorageImpl;

import java.io.FileNotFoundException;
import java.util.Map;
import java.util.Set;

public class BasicNode {

    private static final String LOCALNODE_BASE_FILENAME = "telehash-node";
    private static final int PORT = 42424;

    public static final void main(String[] args) {

        Storage storage = new StorageImpl();

        // load or create a local node
        LocalNode localNode;
        try {
            localNode = storage.readLocalNode(LOCALNODE_BASE_FILENAME);
        } catch (TelehashException e) {
            if (e.getCause() instanceof FileNotFoundException) {
                // no local node found -- create a new one.
                try {
                    localNode = Telehash.get().getCrypto().generateLocalNode();
                    storage.writeLocalNode(localNode, LOCALNODE_BASE_FILENAME);
                } catch (TelehashException e1) {
                    e1.printStackTrace();
                    return;
                }
            } else {
                e.printStackTrace();
                return;
            }
        }

        System.out.println("my hash name: "+localNode.getHashName());

        Set<SeedNode> seeds = null;
        try {
            seeds = storage.readSeeds("seeds.json");
        } catch (TelehashException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        // debug seeds
        System.out.println("seeds:");
        for (SeedNode seed : seeds) {
            System.out.println("  hn " + seed.getHashName());
            for (Map.Entry<CipherSetIdentifier, byte[]> entry : seed
                    .getFingerprints().entrySet()) {
                System.out.println("    cs" + entry.getKey() + " fingerprint: "
                        + Util.bytesToHex(entry.getValue()));
            }
            for (CipherSetIdentifier csid : seed.getCipherSetIds()) {
                System.out.println("    cs " + csid);
                try {
                    HashNamePublicKey publicKey = seed.getPublicKey(csid);
                    if (publicKey != null) {
                        System.out.println("      pub: "
                                + Util.base64Encode(seed.getPublicKey(csid)
                                        .getEncoded()));
                        System.out.println("      fpr: "
                                + Util.bytesToHex(seed.getPublicKey(csid)
                                        .getFingerprint()));
                    }
                } catch (TelehashException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }

        // launch the switch
        final Telehash telehash = new Telehash(localNode);
        final Switch telehashSwitch = new Switch(telehash, seeds, PORT);
        telehash.setSwitch(telehashSwitch);
        try {
            telehashSwitch.start();
        } catch (TelehashException e) {
            e.printStackTrace();
            return;
        }

        try {
            System.out.println("preferred local path: "+
                    telehash.getNetwork().getPreferredLocalPath());
        } catch (TelehashException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        // send packet
        System.out.println("node sending packet to seed.");

        // sleep 4 hours...
        try {
            Thread.sleep(4 * 60 * 60 * 1000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // stop the switch
        telehashSwitch.stop();
    }
}
