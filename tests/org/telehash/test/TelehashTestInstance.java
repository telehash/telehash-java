package org.telehash.test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.telehash.core.Identity;
import org.telehash.core.Node;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.network.impl.InetEndpoint;

public class TelehashTestInstance {
    
    private static final String IDENTITY_BASE_FILENAME = "telehash-node";
    private static final String BASE_DIRECTORY =
            System.getProperty("user.dir")+File.separator+"nodes";
    
    private int mIndex;
    private File mConfigDirectory;
    private int mPort;
    private Identity mIdentity;
    private Set<Node> mSeeds;
    private Telehash mTelehash;
    
    public static List<TelehashTestInstance> createNodes(int numNodes, int startPort) {
        Node seed = null;
        Set<Node> seeds = new HashSet<Node>();
        List<TelehashTestInstance> list = new ArrayList<TelehashTestInstance>(numNodes);
        
        for (int i=0; i<numNodes; i++) {
            File configDirectory = new File(
                    String.format("%s%s%03d", BASE_DIRECTORY, File.separator, i)
            );
            configDirectory.mkdirs();
            
            System.out.println("node "+i+" dir: "+configDirectory);
            TelehashTestInstance node = new TelehashTestInstance(i, configDirectory, startPort+i, seeds);
            node.start();
            list.add(node);
            
            if (seed == null) {
                seed = node.getNode();
                seeds.add(seed);
            }
            
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        return list;
    }

    public TelehashTestInstance(int index, File configDirectory, int port, Set<Node> seeds) {
        mIndex = index;
        mConfigDirectory = configDirectory;
        mPort = port;
        mSeeds = seeds;
    }
    
    public void start() {
        loadIdentity();
        mTelehash = new Telehash(mIdentity);
        
        // store a summary of this node
        try {
            File summaryFile = new File(
                    String.format("%s%s%s", mConfigDirectory, File.separator, "node.txt")
            );
            PrintWriter out = new PrintWriter(summaryFile);
            out.println("index: "+mIndex);
            out.println("hashname: "+Util.bytesToHex(mIdentity.getHashName()));
            System.out.println("pub: "+mIdentity.getPublicKey());
            out.println("rsa pub: "+Util.bytesToHex(mTelehash.getCrypto().sha256Digest(mIdentity.getPublicKey().getDEREncoded())));
            out.println("rsa pri: "+Util.bytesToHex(mTelehash.getCrypto().sha256Digest(mIdentity.getPrivateKey().getDEREncoded())));
            out.close();
        } catch (Throwable e) {
            e.printStackTrace();
        }
        
        // launch the switch
        final Switch telehashSwitch = new Switch(mTelehash, mSeeds, mPort);
        mTelehash.setSwitch(telehashSwitch);
        
        try {
            telehashSwitch.start();
        } catch (TelehashException e) {
            e.printStackTrace();
            return;
        }

    }
    
    public void stop() {
        mTelehash.getSwitch().stop();
        try {
            // give the switch time to stop.
            // TODO: remove this when we make Switch.stop() block until
            // the switch has closed.
            Thread.sleep(1000);
        } catch (InterruptedException e) {}
    }
    
    public Node getNode() {
        try {
            return new Node(
                    mIdentity.getPublicKey(),
                    new InetEndpoint(InetAddress.getLocalHost(), mPort)
            );
        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        } catch (TelehashException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
    
    public Switch getSwitch() {
        return mTelehash.getSwitch();
    }
    
    private void loadIdentity() {
        // load or create an identity
        String identityBaseFilename =
                mConfigDirectory.getAbsolutePath() + File.separator + IDENTITY_BASE_FILENAME;
        try {
            mIdentity = Util.getStorageInstance().readIdentity(identityBaseFilename);
        } catch (TelehashException e) {
            if (e.getCause() instanceof FileNotFoundException) {
                // no identity found -- create a new one.
                try {
                    mIdentity = Util.getCryptoInstance().generateIdentity();
                    Util.getStorageInstance().writeIdentity(mIdentity, identityBaseFilename);
                } catch (TelehashException e1) {
                    e1.printStackTrace();
                    return;
                }
            } else {
                e.printStackTrace();
                return;
            }
        }
    }
    
}
