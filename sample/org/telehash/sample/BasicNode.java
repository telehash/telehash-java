package org.telehash.sample;

import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;

import org.telehash.core.Identity;
import org.telehash.core.Node;
import org.telehash.core.Packet;
import org.telehash.core.PacketFactory;
import org.telehash.core.Switch;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.RSAPublicKey;
import org.telehash.network.impl.InetEndpoint;

public class BasicNode {
    
    private static final String IDENTITY_BASE_FILENAME = "telehash-node";
    private static final int PORT = 5002;
    private static final String SEED_PUBLIC_KEY_FILENAME = "telehash-seed.pub";
    private static final int SEED_PORT = 5001;

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
        
        // read the public key of the seed
        RSAPublicKey seedPublicKey;
        try {
            seedPublicKey =
                    Util.getCryptoInstance().readRSAPublicKeyFromFile(SEED_PUBLIC_KEY_FILENAME);
        } catch (TelehashException e) {
            throw new RuntimeException(e);
        }
        
        // formulate a node object to represent the seed
        InetAddress localhost;
        try {
            localhost = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
        Node seed = new Node(seedPublicKey, new InetEndpoint(localhost, SEED_PORT));
        Set<Node> seeds = new HashSet<Node>();
        seeds.add(seed);

if (true) { return; }
        
        // launch the switch
        Switch telehashSwitch = new Switch(identity, seeds, PORT);
        try {
            telehashSwitch.start();
        } catch (TelehashException e) {
            e.printStackTrace();
            return;
        }

        // send packet
        System.out.println("node sending packet to seed.");
        PacketFactory packetFactory = new PacketFactory();
        try {
            packetFactory.createOpenPacket(seed);
        } catch (TelehashException e1) {
            e1.printStackTrace();
            return;
        }
        telehashSwitch.sendPacket(new Packet());
        
        // pause 1 second
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        // stop the switch
        telehashSwitch.stop();
    }
}
