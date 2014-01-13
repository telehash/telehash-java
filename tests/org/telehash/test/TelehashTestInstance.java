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
import org.telehash.crypto.Crypto;
import org.telehash.crypto.impl.CryptoImpl;
import org.telehash.network.InetPath;
import org.telehash.network.Network;
import org.telehash.network.impl.NetworkImpl;
import org.telehash.storage.Storage;
import org.telehash.storage.impl.StorageImpl;
import org.telehash.test.network.NetworkSimulator;

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
    private Crypto mCrypto = new CryptoImpl();
    private Network mNetwork = new NetworkImpl();
    private Storage mStorage = new StorageImpl();
    
    public static List<TelehashTestInstance> createStarTopology(int numNodes, int startPort) {
        Node seed = null;
        Set<Node> seeds = new HashSet<Node>();
        List<TelehashTestInstance> list = new ArrayList<TelehashTestInstance>(numNodes);
        NetworkSimulator networkSimulator = new NetworkSimulator();
        
        for (int i=0; i<numNodes; i++) {
            File configDirectory = new File(
                    String.format("%s%s%03d", BASE_DIRECTORY, File.separator, i)
            );
            configDirectory.mkdirs();
            
            System.out.println("node "+i+" dir: "+configDirectory);
            TelehashTestInstance node = new TelehashTestInstance(i, configDirectory, 42424, seeds);
            node.setNetwork(networkSimulator.createNode("10.0.0."+i, 42424));
            node.start();
            list.add(node);
            
            if (seed == null) {
                seed = node.getNode();
                seeds.add(seed);
            }
            
            try {
                Thread.sleep(500);
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
    
    public void setCrypto(Crypto crypto) {
        mCrypto = crypto;
    }
    
    public void setNetwork(Network network) {
        mNetwork = network;
    }
    
    public void setStorage(Storage storage) {
        mStorage = storage;
    }
    
    public void start() {
        loadIdentity();
        mTelehash = new Telehash(mIdentity, mCrypto, mStorage, mNetwork);
        
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
    }
    
    public Node getNode() {
        try {
            InetPath path =
                    new InetPath(((InetPath)mNetwork.getPreferredLocalPath()).getAddress(), mPort);
            return new Node(
                    mIdentity.getPublicKey(),
                    path
            );
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
        Storage storage = new StorageImpl();
        String identityBaseFilename =
                mConfigDirectory.getAbsolutePath() + File.separator + IDENTITY_BASE_FILENAME;
        try {
            mIdentity = storage.readIdentity(identityBaseFilename);
        } catch (TelehashException e) {
            if (e.getCause() instanceof FileNotFoundException) {
                // no identity found -- create a new one.
                try {
                    mIdentity = Telehash.get().getCrypto().generateIdentity();
                    storage.writeIdentity(mIdentity, identityBaseFilename);
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
