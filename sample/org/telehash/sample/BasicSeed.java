package org.telehash.sample;

import java.io.FileNotFoundException;

import org.telehash.core.Identity;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.storage.Storage;
import org.telehash.storage.impl.StorageImpl;

public class BasicSeed {
    
    private static final String IDENTITY_BASE_FILENAME = "telehash-seed";
    private static final int PORT = 5001;
    
    public static final void main(String[] args) {
        
        Storage storage = new StorageImpl();

        // load or create an identity
        Identity identity;
        try {
            identity = storage.readIdentity(IDENTITY_BASE_FILENAME);
        } catch (TelehashException e) {
            if (e.getCause() instanceof FileNotFoundException) {
                // no identity found -- create a new one.
                try {
                    identity = Telehash.get().getCrypto().generateIdentity();
                    storage.writeIdentity(identity, IDENTITY_BASE_FILENAME);
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
        Telehash telehash = new Telehash(identity);
        Switch telehashSwitch = new Switch(telehash, null, PORT);
        try {
            telehashSwitch.start();
        } catch (TelehashException e) {
            e.printStackTrace();
            return;
        }

        // allow the switch to run for 30 seconds
        try {
            Thread.sleep(30000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        // stop the switch
        telehashSwitch.stop();
    }
}
