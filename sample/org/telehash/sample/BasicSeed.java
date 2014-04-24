package org.telehash.sample;

import org.telehash.core.LocalNode;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.storage.Storage;
import org.telehash.storage.impl.StorageImpl;

import java.io.FileNotFoundException;

public class BasicSeed {

    private static final String LOCALNODE_BASE_FILENAME = "telehash-seed";
    private static final int PORT = 5001;

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

        // launch the switch
        Telehash telehash = new Telehash(localNode);
        Switch telehashSwitch = new Switch(telehash, null, PORT);
        telehash.setSwitch(telehashSwitch);
        try {
            telehashSwitch.start();
        } catch (TelehashException e) {
            e.printStackTrace();
            return;
        }

        // allow the switch to run for one hour
        try {
            Thread.sleep(3600 * 1000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // stop the switch
        telehashSwitch.stop();
    }
}
