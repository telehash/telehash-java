package org.telehash.sample;

import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;

import org.telehash.core.CompletionHandler;
import org.telehash.core.Identity;
import org.telehash.core.Line;
import org.telehash.core.Node;
import org.telehash.core.OpenPacket;
import org.telehash.core.Packet;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
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
        Node seed;
        try {
            seed = new Node(seedPublicKey, new InetEndpoint(localhost, SEED_PORT));
        } catch (TelehashException e) {
            throw new RuntimeException(e);
        }
        Set<Node> seeds = new HashSet<Node>();
        seeds.add(seed);

        // launch the switch
        Telehash telehash = new Telehash(identity);
        Switch telehashSwitch = new Switch(telehash, seeds, PORT);
        try {
            telehashSwitch.start();
        } catch (TelehashException e) {
            e.printStackTrace();
            return;
        }

        // send packet
        System.out.println("node sending packet to seed.");
        
        /*
        Packet openPacket = new OpenPacket(identity, seed);
        try {
            telehashSwitch.sendPacket(openPacket);
        } catch (TelehashException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        */
        try {
            telehashSwitch.openLine(seed, new CompletionHandler<Line>() {
                @Override
                public void failed(Throwable exc, Object attachment) {
                    System.out.println("line open failed.");
                }
                
                @Override
                public void completed(Line result, Object attachment) {
                    System.out.println("line established: "+result);
                }
            }, null);
        } catch (TelehashException e) {
            e.printStackTrace();
        }
        
        // pause 5 seconds
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        // stop the switch
        telehashSwitch.stop();
    }
}
