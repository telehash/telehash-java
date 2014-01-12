package org.telehash.sample;

import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;

import org.telehash.core.Identity;
import org.telehash.core.Node;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.RSAPublicKey;
import org.telehash.network.impl.InetEndpoint;

public class BasicNode {
    
    private static final String IDENTITY_BASE_FILENAME = "telehash-node";
    private static final int PORT = 42424;

    public static final void main(String[] args) {
        
        // load or create an identity
        Identity identity;
        try {
            identity = Util.getStorageInstance().readIdentity(IDENTITY_BASE_FILENAME);
        } catch (TelehashException e) {
            if (e.getCause() instanceof FileNotFoundException) {
                // no identity found -- create a new one.
                try {
                    identity = Util.getCryptoInstance().generateIdentity();
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
        
        System.out.println("my hash name: "+Util.bytesToHex(identity.getHashName()));
        
        Set<Node> seeds = null;
        try {
            seeds = Util.getStorageInstance().readSeeds("seeds.json");
        } catch (TelehashException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }
        
        // launch the switch
        final Telehash telehash = new Telehash(identity);
        final Switch telehashSwitch = new Switch(telehash, seeds, PORT);
        telehash.setSwitch(telehashSwitch);
        try {
            telehashSwitch.start();
        } catch (TelehashException e) {
            e.printStackTrace();
            return;
        }
        
        try {
            System.out.println("preferred local endpoint: "+telehash.getNetwork().getPreferredLocalEndpoint());
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
