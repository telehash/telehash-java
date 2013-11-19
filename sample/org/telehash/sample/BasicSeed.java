package org.telehash.sample;

import java.io.FileNotFoundException;

import org.telehash.core.Identity;
import org.telehash.core.Switch;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;

public class BasicSeed {
    
    private static final String IDENTITY_BASE_FILENAME = "telehash-seed";
    
    public static final void main(String[] args) {

        // load or create an identity
        Identity identity;
        try {
            identity = Util.getStorageInstance().readIdentity(IDENTITY_BASE_FILENAME);
        } catch (TelehashException e) {
            if (e.getCause() instanceof FileNotFoundException) {
                // no identity found -- create a new one.
                identity = Util.getCryptoInstance().generateIdentity();
                try {
                    Util.getStorageInstance().writeIdentity(identity, IDENTITY_BASE_FILENAME);
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
        Switch telehashSwitch = new Switch(identity, null);
        telehashSwitch.loop();        
    }
}
