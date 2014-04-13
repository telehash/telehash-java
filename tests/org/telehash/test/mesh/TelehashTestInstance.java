package org.telehash.test.mesh;

import org.telehash.core.Identity;
import org.telehash.core.Log;
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TelehashTestInstance {

    private static final String IDENTITY_BASE_FILENAME = "telehash-node";
    private static final String BASE_DIRECTORY =
            System.getProperty("user.dir")+File.separator+"nodes";
    private static final int PORT = 42424;

    private int mIndex;
    private File mConfigDirectory;
    private int mPort;
    private Identity mIdentity;
    private Set<Node> mSeeds;
    private Telehash mTelehash;
    private Crypto mCrypto = new CryptoImpl();
    private Network mNetwork = new NetworkImpl();
    private Storage mStorage = new StorageImpl();

    private static void dumpNode(TelehashTestInstance node) {
        String path;
        try {
            path = node.mNetwork.getPreferredLocalPath().toString();
        } catch (TelehashException e) {
            path = "?";
        }
        Log.i("  ["+node.mIndex+"] "+node.mIdentity.getHashName()+" "+path);
    }

    private static void dumpNodeList(List<TelehashTestInstance> list) {
        for (TelehashTestInstance i : list) {
            dumpNode(i);
        }
    }

    private static TelehashTestInstance createInstance(
            NetworkSimulator networkSimulator,
            int index,
            Node seed
    ) {
        Set<Node> seeds = null;
        if (seed != null) {
            seeds = new HashSet<Node>();
            seeds.add(seed);
        }
        TelehashTestInstance node = new TelehashTestInstance(index, PORT, seeds);
        node.setNetwork(networkSimulator.createNode("10.0.0."+index, PORT));
        node.start();

        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return node;
    }

    public static List<TelehashTestInstance> createStarTopology(int numNodes) {
        Node seed = null;
        List<TelehashTestInstance> list = new ArrayList<TelehashTestInstance>(numNodes);
        NetworkSimulator networkSimulator = new NetworkSimulator();

        for (int i=0; i<numNodes; i++) {
            TelehashTestInstance instance = createInstance(networkSimulator, i, seed);
            if (seed == null) {
                seed = instance.getNode();
            }
            list.add(instance);
        }

        Log.i("Telehash star topology created: ");
        dumpNodeList(list);

        return list;
    }

    public static List<TelehashTestInstance> createThreeLevelTopology() {
        List<TelehashTestInstance> list = new ArrayList<TelehashTestInstance>(5);
        NetworkSimulator networkSimulator = new NetworkSimulator();
        TelehashTestInstance i0 = createInstance(networkSimulator, 0, null);
        TelehashTestInstance i1 = createInstance(networkSimulator, 1, i0.getNode());
        TelehashTestInstance i2 = createInstance(networkSimulator, 2, i0.getNode());
        TelehashTestInstance i3 = createInstance(networkSimulator, 3, i1.getNode());
        TelehashTestInstance i4 = createInstance(networkSimulator, 4, i2.getNode());
        list.add(i0);
        list.add(i1);
        list.add(i2);
        list.add(i3);
        list.add(i4);
        Log.i("Telehash three-level topology created: ");
        dumpNodeList(list);
        return list;
    }

    public TelehashTestInstance(int index, int port, Set<Node> seeds) {
        File configDirectory = new File(
                String.format("%s%s%03d", BASE_DIRECTORY, File.separator, index)
        );
        configDirectory.mkdirs();
        Log.i("creating test instance ["+index+"] dir: "+configDirectory);

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
            out.println("hashname: "+mIdentity.getHashName());
            Log.i("pub: "+mIdentity.getPublicKey());
            out.println("rsa pub: "+Util.bytesToHex(
                    mTelehash.getCrypto().sha256Digest(mIdentity.getPublicKey().getEncoded())
            ));
            out.println("rsa pri: "+Util.bytesToHex(
                    mTelehash.getCrypto().sha256Digest(mIdentity.getPrivateKey().getEncoded())
            ));
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
