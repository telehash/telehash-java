package org.telehash.dht;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.json.JSONArray;
import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.HashName;
import org.telehash.core.Line;
import org.telehash.core.Node;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.RSAPublicKey;
import org.telehash.network.Endpoint;
import org.telehash.network.impl.InetEndpoint;

public class DHT {
    
    public static final String SEEK_KEY = "seek";
    public static final String SEE_KEY = "see";
    public static final String PEER_KEY = "peer";
    public static final String CONNECT_KEY = "connect";

    private Telehash mTelehash;
    private Node mLocalNode;
    
    private NodeTracker mNodeTracker;
    
private Node xSeed;
    public DHT(Telehash telehash, Node localNode, Set<Node> seeds) {
        mTelehash = telehash;
        mLocalNode = localNode;
        mNodeTracker = new NodeTracker(localNode);
        
        // install seeds in k-buckets.
        if (seeds != null) {
xSeed = seeds.iterator().next();
            for (Node node : seeds) {
                mNodeTracker.submitNode(node);
            }
        }
    }

    public void init() {
        // register to receive channel packets for our types
        mTelehash.getSwitch().registerChannelHandler(SEEK_KEY, mChannelHandler);
        mTelehash.getSwitch().registerChannelHandler(PEER_KEY, mChannelHandler);
        mTelehash.getSwitch().registerChannelHandler(CONNECT_KEY, mChannelHandler);
        
        // TODO: implement bucket refresh
        
        // TODO: implement bootstrap (refresh all buckets)

        /*
        Set<Node> closestNodes = mNodeTracker.getClosestNodes(xSeed.getHashName(), 12);
        System.out.println("closest nodes in tracker:");
        for (Node node : closestNodes) {
            System.out.println(node);
        }

        NodeSeekRequest nodeSeeker = new NodeSeekRequest(mTelehash, xSeed, mLocalNode.getHashName(), new NodeSeekRequest.Handler() {
            @Override
            public void handleError(NodeSeekRequest seek, Throwable e) {
                System.out.println("cannot seek node: "+e);
            }
            @Override
            public void handleCompletion(NodeSeekRequest seek) {
                System.out.println("found nodes: ");
                for (Node node : seek.getResultNodes()) {
                    System.out.println(node);
                }
            }
        });
        nodeSeeker.start();
        */
        
        HashName seedName = new HashName(Util.hexToBytes("484aa23a17d259906144d36d7ccddbb583a63702a9253c29d41cff13a07954a6"));
        NodeLookupTask lookup = new NodeLookupTask(mTelehash, mNodeTracker, seedName);
        lookup.start();
    }
    
    public void handleNewLine(Line line) {
        mNodeTracker.submitNode(line.getRemoteNode());
        // TODO: relay to refresher?
    }
    
    /**
     * Return the hashspace logarithmic distance between the two hashnames. This
     * is defined as the binary logarithm of the xor of the two hashnames (or
     * -1, if the hashnames are identical). This logarithmic distance metric is
     * suitable for use as an index into an array of buckets. (Unless the
     * returned value is -1 indicating the hashnames are the same, in which case
     * nothing should be stored in a bucket.)
     * 
     * The returned value will always be between -1 and 255, inclusive.
     * 
     * @param A
     *            The first hashname.
     * @param B
     *            The second hashname.
     * @return The distance, or -1 if the hashnames are identical.
     */
    public static int logDistance(HashName A, HashName B) {
        // opportunities for optimization abound.
        // http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious
        
        if (A == null || B == null) {
            throw new IllegalArgumentException("invalid hashname");
        }
        byte[] ba = A.getBytes();
        byte[] bb = B.getBytes();
        for (int i=0; i<HashName.SIZE; i++) {
            int c = ba[i] ^ bb[i];
            if (c != 0) {
                for (int j=0; j<8; j++) {
                    if ((c & 0x80) != 0) {
                        return (HashName.SIZE-i-1)*8 + (8-j-1);
                    }
                    c = c << 1;
                }
            }
        }
        return -1;
    }
    
    private ChannelHandler mChannelHandler = new ChannelHandler() {
        public void handleError(Channel channel, Throwable error) {
            
        };
        public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
            String type = channelPacket.getType();
            if (type == null) {
                return;
            }
            try {
                if (type.equals(SEEK_KEY)) {
                    handleSeek(channel, channelPacket);
                } else if (type.equals(PEER_KEY)) {
                    handlePeer(channel, channelPacket);
                } else if (type.equals(CONNECT_KEY)) {
                    handleConnect(channel, channelPacket);
                }
            } catch (Throwable e) {
                // best-effort only
                e.printStackTrace();
            }
        };
    };
    
    private static final int MAX_SEEK_NODES_RETURNED = 9;

    private void handleSeek(Channel channel, ChannelPacket channelPacket) {
        String seekString = (String) channelPacket.get(PEER_KEY);
        if (seekString == null || seekString.isEmpty()) {
            return;
        }
        HashName target = new HashName(Util.hexToBytes(seekString));
        Set<Node> nodes = mNodeTracker.getClosestNodes(target, MAX_SEEK_NODES_RETURNED);
        
        JSONArray see = new JSONArray();
        for (Node node : nodes) {
            if (node.getEndpoint() instanceof InetEndpoint) {
                InetEndpoint endpoint = (InetEndpoint)node.getEndpoint();
                String seeNode =
                        node.getHashName().asHex() + "," +
                        endpoint.getAddress().getHostAddress() + "," +
                        endpoint.getPort(); 
                see.put(seeNode);
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
    
    private void handlePeer(Channel channel, ChannelPacket channelPacket) {
        String peerString = (String) channelPacket.get(PEER_KEY);
        if (peerString == null || peerString.isEmpty()) {
            return;
        }
        HashName target = new HashName(Util.hexToBytes(peerString));
        Line line = mTelehash.getSwitch().getLineByHashName(target);
        if (line == null) {
            // no line to the target
            return;
        }
        
        Node originatingNode = channel.getRemoteNode();
        if (! (originatingNode.getEndpoint() instanceof InetEndpoint)) {
            return;
        }
        InetEndpoint endpoint = (InetEndpoint)originatingNode.getEndpoint();
        
        // send a connect message to the target with the originator's information
        Channel newChannel = line.openChannel(CONNECT_KEY, null);
        Map<String,Object> fields = new HashMap<String,Object>();
        fields.put("ip", endpoint.getAddress());
        fields.put("port", endpoint.getPort());
        try {
            newChannel.send(
                    channel.getRemoteNode().getPublicKey().getDEREncoded(),
                    fields,
                    true
            );
        } catch (TelehashException e) {
            // best-effort only
            e.printStackTrace();
        }
    }

    private void handleConnect(Channel channel, ChannelPacket channelPacket) throws TelehashException {
        String ipString = (String) channelPacket.get("ip");
        if (ipString == null || ipString.isEmpty()) {
            return;
        }
        int port = ((Number)channelPacket.get("port")).intValue();
        byte[] body = channelPacket.getBody();
        if (body == null) {
            return;
        }
        RSAPublicKey publicKey = mTelehash.getCrypto().decodeRSAPublicKey(body);
        InetAddress inetAddress;
        try {
            // TODO: is this safe?
            inetAddress = InetAddress.getByName(ipString);
        } catch (UnknownHostException e) {
            throw new TelehashException(e);
        }
        Endpoint endpoint = new InetEndpoint(inetAddress, port);
        Node node = new Node(publicKey, endpoint);
        mTelehash.getSwitch().openLine(node, null, null);
    }
}
