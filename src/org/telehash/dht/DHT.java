package org.telehash.dht;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.FingerprintSet;
import org.telehash.core.HashName;
import org.telehash.core.Line;
import org.telehash.core.Log;
import org.telehash.core.Node;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.CipherSet;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.InetPath;
import org.telehash.network.Path;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DHT {

    private static final String SEEK_TYPE = "seek";
    private static final String LINK_TYPE = "link";
    private static final String CONNECT_TYPE = "connect";
    private static final String SEEK_KEY = "seek";
    private static final String SEED_KEY = "seed";
    private static final String SEE_KEY = "see";

    public static final String PEER_TYPE = "peer";
    public static final String PEER_KEY = "peer";

    private Telehash mTelehash;
    private Node mLocalNode;

    private NodeTracker mNodeTracker;

    public DHT(Telehash telehash, Node localNode, Set<Node> seeds) {
        mTelehash = telehash;
        mLocalNode = localNode;
        mNodeTracker = new NodeTracker(localNode);

        // install seeds in k-buckets.
        if (seeds != null && (! seeds.isEmpty())) {
            for (Node node : seeds) {
                mNodeTracker.submitNode(node);
            }
        }
    }

    public void init() {
        // register to receive channel packets for our types
        mTelehash.getSwitch().registerChannelHandler(SEEK_TYPE, mChannelHandler);
        mTelehash.getSwitch().registerChannelHandler(LINK_TYPE, mChannelHandler);
        mTelehash.getSwitch().registerChannelHandler(PEER_TYPE, mChannelHandler);
        mTelehash.getSwitch().registerChannelHandler(CONNECT_TYPE, mChannelHandler);

        // TODO: implement bucket refresh

        // TODO: implement bootstrap (refresh all buckets)

        /*
        Set<Node> closestNodes = mNodeTracker.getClosestNodes(xSeed.getHashName(), 12);
        Log.i("closest nodes in tracker:");
        for (Node node : closestNodes) {
            Log.i(node);
        }

        NodeSeekRequest nodeSeeker = new NodeSeekRequest(mTelehash, xSeed, mLocalNode.getHashName(), new NodeSeekRequest.Handler() {
            @Override
            public void handleError(NodeSeekRequest seek, Throwable e) {
                Log.i("cannot seek node: "+e);
            }
            @Override
            public void handleCompletion(NodeSeekRequest seek) {
                Log.i("found nodes: ");
                for (Node node : seek.getResultNodes()) {
                    Log.i(node);
                }
            }
        });
        nodeSeeker.start();
        */

        // TODO: remove this hard-coded seed lookup.
        /*
        HashName seedName = new HashName(Util.hexToBytes("484aa23a17d259906144d36d7ccddbb583a63702a9253c29d41cff13a07954a6"));
        NodeLookupTask lookup = new NodeLookupTask(mTelehash, mNodeTracker, seedName, null);
        lookup.start();
        */
        mNodeTracker.refreshBuckets();
    }

    public void close() {
        mNodeTracker.dump();
    }

    public void handleNewLine(Line line) {
        mNodeTracker.submitNode(line.getRemoteNode());
        // TODO: relay to refresher?
    }

    public void submitNode(Node node) {
        // TODO
        // 1. is a line already open for this node?
        // 2. open line
        // 3. open link channel
    }

    /**
     * Return a random hashname located with the specified bucket
     * (relative to the provided origin hashname).
     *
     * @param originHashName The origin hashname.  (i.e., your own hashname.)
     * @param bucket The bucket index.
     * @return The random hashname within the bucket.
     */
    public static HashName getRandomHashName(HashName originHashName, int bucket) {
        // start with the origin hashname
        BigInteger hash = new BigInteger(1, originHashName.getBytes());

        // randomize all bits below the bucket bit
        if (bucket > 0) {
            byte[] randomBytes = Telehash.get().getCrypto().getRandomBytes(HashName.SIZE);
            BigInteger random = new BigInteger(1, randomBytes);
            BigInteger mask = BigInteger.ONE.shiftLeft(bucket).subtract(BigInteger.ONE);

            hash = hash.andNot(mask);  // chop off right part of origin
            random = random.and(mask); // chop off left part of random
            hash = hash.or(random);    // combine left-origin and right-random
        }

        // flip the bucket bit
        hash = hash.flipBit(bucket);

        // the byte array may have an extra leading byte to hold the sign bit,
        // so trim to size.
        byte[] randomHashNameBytes = Util.fixedSizeBytes(hash.toByteArray(), HashName.SIZE);
        return new HashName(randomHashNameBytes);
    }

    private ChannelHandler mChannelHandler = new ChannelHandler() {
        @Override
        public void handleError(Channel channel, Throwable error) {

        };
        @Override
        public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
            String type = channelPacket.getType();
            if (type == null) {
                return;
            }
            try {
                if (type.equals(SEEK_TYPE)) {
                    handleSeek(channel, channelPacket);
                } else if (type.equals(LINK_TYPE)) {
                    handleLink(channel, channelPacket);
                } else if (type.equals(PEER_TYPE)) {
                    handlePeer(channel, channelPacket);
                } else if (type.equals(CONNECT_TYPE)) {
                    handleConnect(channel, channelPacket);
                }
            } catch (Throwable e) {
                // best-effort only
                e.printStackTrace();
            }
        }
        @Override
        public void handleOpen(Channel channel) {
            // not needed since this is a listening channel.
        };
    };

    private static final int MAX_SEEK_NODES_RETURNED = 9;

    private void handleSeek(Channel channel, ChannelPacket channelPacket) {
        String seekString = (String) channelPacket.get(SEEK_KEY);
        if (seekString == null || seekString.isEmpty()) {
            return;
        }

        // support prefix seeks by coercing the string to 64 characters.
        if (seekString.length() < HashName.SIZE*2) {
            char[] chars = new char[HashName.SIZE*2];
            Arrays.fill(chars, '0');
            seekString.getChars(0, seekString.length(), chars, 0);
            seekString = new String(chars);
        }

        HashName target = new HashName(Util.hexToBytes(seekString));
        Set<Node> nodes = mNodeTracker.getClosestNodes(target, MAX_SEEK_NODES_RETURNED);

        Log.i("processing: seek "+target);

        JSONArray see = new JSONArray();
        for (Node node : nodes) {
            if (node.getPath() instanceof InetPath) {
                InetPath path = (InetPath)node.getPath();
                String seeNode =
                        node.getHashName().asHex() + "," +
                        path.getAddress().getHostAddress() + "," +
                        path.getPort();
                see.put(seeNode);
                Log.i("\tsee: "+seeNode);
            }
        }
        Map<String,Object> fields = new HashMap<String,Object>();
        fields.put(SEE_KEY, see);
        try {
            channel.send(null, fields, true);
        } catch (TelehashException e) {
            return;
        }
    }

    private void handleLink(Channel channel, ChannelPacket channelPacket) {
        // TODO: handle the "seed" boolean
        channelPacket.get(SEED_KEY);

        Set<Node> seeNodes;
        try {
            seeNodes = parseSee(channelPacket.get(SEE_KEY), mLocalNode);
        } catch (TelehashException e) {
            Log.e("bad see object in link channel");
            return;
        }

        // submit seeNodes to DHT for possible inclusion in buckets.
        for (Node node : seeNodes) {
            submitNode(node);
        }

        // TODO: if this is a keepalive, then respond in kind.
        // TODO: (even if it's not a keepalive!)

        // TODO: complete!
    }

    private void handlePeer(Channel channel, ChannelPacket channelPacket) {
        String peerString = (String) channelPacket.get(PEER_KEY);
        if (peerString == null || peerString.isEmpty()) {
            return;
        }
        HashName target = new HashName(Util.hexToBytes(peerString));
        Line line = mTelehash.getSwitch().getLineManager().getLineByHashName(target);
        if (line == null) {
            // no line to the target
            return;
        }

        Node originatingNode = channel.getRemoteNode();
        if (! (originatingNode.getPath() instanceof InetPath)) {
            return;
        }
        InetPath path = (InetPath)originatingNode.getPath();
        if (originatingNode.getFingerprints() == null) {
            Log.e("peer originator has no fingerprints: "+originatingNode.getHashName());
            return;
        }

        // cipher set matchmaking
        CipherSetIdentifier csid = Node.bestCipherSet(originatingNode, line.getRemoteNode());
        if (csid == null) {
            Log.e("error while matching cipher sets", new TelehashException("null csid"));
            return;
        }

        // send a connect message to the target with the originator's information
        Channel newChannel = line.openChannel(CONNECT_TYPE, null);
        List<JSONObject> paths = new ArrayList<JSONObject>(1);
        paths.add(path.toJSONObject());
        Map<String,Object> fields = new HashMap<String,Object>();
        fields.put("from", originatingNode.getFingerprints().toJSON());
        fields.put("paths", paths);
        try {
            newChannel.send(
                    channel.getRemoteNode().getPublicKey(csid).getEncoded(),
                    fields,
                    true
            );
        } catch (TelehashException e) {
            // best-effort only
            e.printStackTrace();
        }
    }

    private void handleConnect(Channel channel, ChannelPacket channelPacket) throws TelehashException {
        // parse the paths
        Object pathsObject = channelPacket.get("paths");
        if (! (pathsObject instanceof JSONArray)) {
            return;
        }
        List<Path> paths = Path.parsePathArray((JSONArray)pathsObject);
        if (paths == null || paths.isEmpty()) {
            return;
        }

        // TODO: support more than the first path
        Path path = paths.get(0);

        // cipher set matchmaking
        Object fromObject = channelPacket.get("from");
        if (fromObject == null) {
            throw new TelehashException("connect packet is missing from!");
        }
        if (! (fromObject instanceof JSONObject)) {
            throw new TelehashException("expected JSONObject!");
        }
        FingerprintSet fingerprints = new FingerprintSet((JSONObject)fromObject);
        CipherSetIdentifier csid = FingerprintSet.bestCipherSet(
                mTelehash.getIdentity().getNode().getFingerprints(),
                fingerprints
        );
        if (csid == null) {
            Log.e("error while matching cipher sets", new TelehashException("null csid"));
        }

        // extract the peer's public key
        byte[] body = channelPacket.getBody();
        if (body == null) {
            return;
        }
        CipherSet cipherSet = mTelehash.getCrypto().getCipherSet(csid);
        if (cipherSet == null) {
            throw new TelehashException("unknown cipher set id in connect");
        }
        HashNamePublicKey publicKey = cipherSet.decodeHashNamePublicKey(body);

        Node node = new Node(fingerprints.getHashName(), csid, publicKey, path);
        node.updateFingerprints(fingerprints);
        mTelehash.getSwitch().getLineManager().openLine(node, false, null, null);
    }

    private static Set<Node> parseSee(
            Object seeObject,
            Node referringNode
    ) throws TelehashException {
        if (! (seeObject instanceof JSONArray)) {
            throw new TelehashException("'see' object not an array");
        }
        JSONArray seeNodes = (JSONArray)seeObject;

        Set<Node> sees = new HashSet<Node>(seeNodes.length());
        for (int i=0; i<seeNodes.length(); i++) {
            String seeNode;
            try {
                seeNode = seeNodes.getString(i);
            } catch (JSONException e) {
                throw new TelehashException(e);
            }
            String[] parts = seeNode.split(",", 3);
            if (parts.length < 3) {
                // TODO: support see nodes with hashname-only?  (i.e. reachable via non-IP paths)
                throw new TelehashException("invalid see record");
            }
            HashName hashName = new HashName(Util.hexToBytes(parts[0]));
            Path path;
            try {
                path = Telehash.get().getNetwork().parsePath(
                        parts[1], Integer.parseInt(parts[2])
                );
                Node node = new Node(hashName, path);
                node.setReferringNode(referringNode);
                sees.add(node);
            } catch (NumberFormatException e) {
                throw new TelehashException(e);
            }
        }
        return sees;
    }

    /**
     * Initiate a node lookup of the specified hashname. The caller should
     * maintain a reference to the returned NodeLookupTask until it is no longer
     * needed, to avoid early garbage collection.
     *
     * @param hashName
     * @param handler
     * @return
     */
    public NodeLookupTask nodeLookup(HashName hashName, NodeLookupTask.Handler handler) {
        NodeLookupTask lookup = new NodeLookupTask(mTelehash, mNodeTracker, hashName, handler);
        lookup.start();
        return lookup;
    }
}