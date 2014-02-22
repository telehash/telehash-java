package org.telehash.dht;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.HashName;
import org.telehash.core.Line;
import org.telehash.core.Log;
import org.telehash.core.Node;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.network.Path;

/**
 * Handle a single seek/see transaction.
 */
public class NodeSeekRequest {
    
    private static final String SEEK_TYPE = "seek";
    private static final String SEEK_KEY = "seek";
    private static final String SEE_KEY = "see";

    public static interface Handler {
        void handleError(NodeSeekRequest seek, Throwable e);
        void handleCompletion(NodeSeekRequest seek);
    }
    
    private Telehash mTelehash;
    private Node mQueryNode;
    private HashName mTargetHashName;
    private Handler mHandler;
    private Line mLine;
    private Set<Node> mResultNodes;
    
    public NodeSeekRequest(Telehash telehash, Node queryNode, HashName targetHashName, Handler handler) {
        mTelehash = telehash;
        mQueryNode = queryNode;
        mTargetHashName = targetHashName;
        mHandler = handler;
    }
    
    public Set<Node> getResultNodes() {
        return mResultNodes;
    }
    
    public void start() {
        mTelehash.getSwitch().openChannel(mQueryNode, SEEK_TYPE, new ChannelHandler() {
            @Override
            public void handleError(Channel channel, Throwable error) {
                Log.i("seek channel error");
                fail(error);
            }
            @Override
            public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
                Log.i("seek channel incoming");
                parseResult(channelPacket);
            }
            @Override
            public void handleOpen(Channel channel) {
                Log.i("seek channel open");
                Map<String,Object> fields = new HashMap<String,Object>();
                
                // To product the user's privacy, only provide enough of the target hashname
                // to get useful results -- the distance to the query node plus one bytes.
                HashName localHashName = mTelehash.getIdentity().getHashName();
                byte[] target;
                if (! mTargetHashName.equals(localHashName)) {
                    int prefixLength = mQueryNode.getHashName().distanceMagnitude(localHashName)+1;
                    if (prefixLength > HashName.SIZE) {
                        prefixLength = HashName.SIZE;
                    }
                    target = new byte[prefixLength];
                    System.arraycopy(mTargetHashName.getBytes(), 0, target, 0, prefixLength);
                } else {
                    target = mTargetHashName.getBytes();
                }
                
                fields.put(SEEK_KEY, Util.bytesToHex(target));
                try {
                    channel.send(null, fields, false);
                } catch (TelehashException e) {
                    fail(e);
                    return;
                }
            }
        });
    }
    
    private void parseResult(ChannelPacket channelPacket) {
        Object seeObject = channelPacket.get(SEE_KEY);
        if (! (seeObject instanceof JSONArray)) {
            fail(new TelehashException("'see' object not an array"));
            return;
        }
        JSONArray seeNodes = (JSONArray)seeObject;
        
        mResultNodes = new HashSet<Node>();
        for (int i=0; i<seeNodes.length(); i++) {
            String seeNode;
            try {
                seeNode = seeNodes.getString(i);
            } catch (JSONException e) {
                fail(e);
                return;
            }
            String[] parts = seeNode.split(",", 3);
            if (parts.length < 3) {
                fail(new TelehashException("invalid see record"));
                return;
            }
            HashName hashName = new HashName(Util.hexToBytes(parts[0]));
            Path path;
            try {
                path = mTelehash.getNetwork().parsePath(
                        parts[1], Integer.parseInt(parts[2])
                );
                Node node = new Node(hashName, path);
                node.setReferringNode(mQueryNode);
                mResultNodes.add(node);
            } catch (NumberFormatException e) {
                fail(e);
                return;
            } catch (TelehashException e) {
                fail(e);
                return;
            }
        }

        // signal success/finish
        mHandler.handleCompletion(this);
    }
    
    private void fail(Throwable e) {
        mHandler.handleError(this, e);
    }
}
