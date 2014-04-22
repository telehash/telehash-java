package org.telehash.test.mesh;

import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.LocalNode;
import org.telehash.core.Log;
import org.telehash.core.SeedNode;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.HashNamePublicKey;
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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;

public class TelehashTestInstance {

    private static final String LOCALNODE_BASE_FILENAME = "telehash-node";
    private static final String BASE_DIRECTORY =
            System.getProperty("user.dir")+File.separator+"nodes";
    private static final int PORT = 42424;

    private int mIndex;
    private File mConfigDirectory;
    private int mPort;
    private LocalNode mLocalNode;
    private Set<SeedNode> mSeeds;
    private Telehash mTelehash;
    private Crypto mCrypto = new CryptoImpl();
    private Network mNetwork = new NetworkImpl();
    private Storage mStorage = new StorageImpl();

    private static void dumpNode(StringBuilder sb, TelehashTestInstance node) {
        String path;
        try {
            path = node.mNetwork.getPreferredLocalPath().toString();
        } catch (TelehashException e) {
            path = "?";
        }
        sb.append("  ["+node.mIndex+"] "+node.mLocalNode.getHashName()+" "+path+"\n");
    }

    private static String dumpNodeList(List<TelehashTestInstance> list) {
        StringBuilder sb = new StringBuilder();
        for (TelehashTestInstance i : list) {
            dumpNode(sb, i);
        }
        return sb.toString();
    }

    private static SeedNode localNodeToSeedNode(LocalNode localNode) {
        SeedNode seedNode = new SeedNode(
                localNode.getFingerprints(),
                localNode.getPublicKeys(),
                localNode.getPaths()
        );
        return seedNode;
    }

    private static TelehashTestInstance createInstance(
            NetworkSimulator networkSimulator,
            int index,
            SeedNode seedNode
    ) {
        SeedNode seed;
        if (seedNode == null) {
            seed = null;
        } else {
            seed = new SeedNode(
                    seedNode.getFingerprints(),
                    seedNode.getPublicKeys(),
                    seedNode.getPaths()
            );
        }

        Set<SeedNode> seeds = null;
        if (seed != null) {
            seeds = new HashSet<SeedNode>();
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
        SeedNode seed = null;
        List<TelehashTestInstance> list = new ArrayList<TelehashTestInstance>(numNodes);
        NetworkSimulator networkSimulator = new NetworkSimulator();

        for (int i=0; i<numNodes; i++) {
            TelehashTestInstance instance = createInstance(networkSimulator, i, seed);
            if (seed == null) {
                seed = localNodeToSeedNode(instance.getNode());
            }
            list.add(instance);
        }

        Log.i("Telehash star topology created:\n"+dumpNodeList(list));

        return list;
    }

    public static List<TelehashTestInstance> createThreeLevelTopology() {
        List<TelehashTestInstance> list = new ArrayList<TelehashTestInstance>(5);
        NetworkSimulator networkSimulator = new NetworkSimulator();
        TelehashTestInstance i0 = createInstance(networkSimulator, 0, null);
        TelehashTestInstance i1 = createInstance(networkSimulator, 1, i0.getNodeAsSeed());
        TelehashTestInstance i2 = createInstance(networkSimulator, 2, i0.getNodeAsSeed());
        TelehashTestInstance i3 = createInstance(networkSimulator, 3, i1.getNodeAsSeed());
        TelehashTestInstance i4 = createInstance(networkSimulator, 4, i2.getNodeAsSeed());
        list.add(i0);
        list.add(i1);
        list.add(i2);
        list.add(i3);
        list.add(i4);
        Log.i("Telehash three-level topology created: \n"+dumpNodeList(list));
        return list;
    }

    /**
     *
     * @param depth The depth of the tree.  Number of nodes will be 2^depth-1.
     * @return The list of Telehash test instances.
     */
    public static List<TelehashTestInstance> createLargeScaleTopology(int depth) {
        // 63 nodes in a tree

        List<TelehashTestInstance> list = new ArrayList<TelehashTestInstance>();
        List<TelehashTestInstance> leafNodes = new ArrayList<TelehashTestInstance>();
        NetworkSimulator networkSimulator = new NetworkSimulator();
        int index = 0;
        TelehashTestInstance root = createInstance(networkSimulator, index++, null);
        list.add(root);
        leafNodes.add(root);

        for (int i=0; i<(depth-1); i++) {
            List<TelehashTestInstance> oldLeafNodes = leafNodes;
            leafNodes = new ArrayList<TelehashTestInstance>();

            for (TelehashTestInstance tti : oldLeafNodes) {
                TelehashTestInstance tti0 =
                        createInstance(networkSimulator, index++, tti.getNodeAsSeed());
                TelehashTestInstance tti1 =
                        createInstance(networkSimulator, index++, tti.getNodeAsSeed());
                leafNodes.add(tti0);
                leafNodes.add(tti1);
                list.add(tti0);
                list.add(tti1);
            }
        }

        Log.i("Telehash large scale topology created: ("+index+" nodes)\n"+dumpNodeList(list));
        return list;
    }

    public TelehashTestInstance(int index, int port, Set<SeedNode> seeds) {
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
        loadLocalNode();
        mTelehash = new Telehash(mLocalNode, mCrypto, mStorage, mNetwork);

        // store a summary of this node
        try {
            File summaryFile = new File(
                    String.format("%s%s%s", mConfigDirectory, File.separator, "node.txt")
            );
            PrintWriter out = new PrintWriter(summaryFile);
            out.println("index: "+mIndex);
            out.println("hashname: "+mLocalNode.getHashName());
            SortedMap<CipherSetIdentifier, HashNamePublicKey> publicKeys =
                    mLocalNode.getPublicKeys();
            for (Map.Entry<CipherSetIdentifier, HashNamePublicKey> entry : publicKeys.entrySet()) {
                CipherSetIdentifier csid = entry.getKey();
                Log.i(""+csid+" pub: "+entry.getValue());
                out.println(""+csid+" pub: "+Util.bytesToHex(
                        mTelehash.getCrypto().sha256Digest(
                                mLocalNode.getPublicKey(csid).getEncoded()
                        )
                ));
                out.println(""+csid+" pri: "+Util.bytesToHex(
                        mTelehash.getCrypto().sha256Digest(
                                mLocalNode.getPrivateKey(csid).getEncoded()
                        )
                ));
            }
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

    public LocalNode getNode() {
        try {
            InetPath path =
                    new InetPath(((InetPath)mNetwork.getPreferredLocalPath()).getAddress(), mPort);
            mLocalNode.setPaths(Collections.singleton(path));
            return mLocalNode;
        } catch (TelehashException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    public SeedNode getNodeAsSeed() {
        return localNodeToSeedNode(getNode());
    }

    public Switch getSwitch() {
        return mTelehash.getSwitch();
    }

    private void loadLocalNode() {
        // load or create a local node
        Storage storage = new StorageImpl();
        String localNodeBaseFilename =
                mConfigDirectory.getAbsolutePath() + File.separator + LOCALNODE_BASE_FILENAME;
        try {
            mLocalNode = storage.readLocalNode(localNodeBaseFilename);
        } catch (TelehashException e) {
            if (e.getCause() instanceof FileNotFoundException) {
                // no local node found -- create a new one.
                try {
                    mLocalNode = Telehash.get().getCrypto().generateLocalNode();
                    storage.writeLocalNode(mLocalNode, localNodeBaseFilename);
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
