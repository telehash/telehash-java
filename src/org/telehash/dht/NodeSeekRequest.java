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
import org.telehash.core.CompletionHandler;
import org.telehash.core.HashName;
import org.telehash.core.Line;
import org.telehash.core.Node;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.network.Endpoint;

/**
 * Handle a single seek/see transaction.
 */
public class NodeSeekRequest {
    
    private static final String SEEK_TYPE = "seek";

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
        Line line = mTelehash.getSwitch().getLineByNode(mQueryNode);
        if (line != null) {
            mLine = line;
            sendSeek();
        } else {
            try {
                mTelehash.getSwitch().openLine(mQueryNode, new CompletionHandler<Line>() {
                    @Override
                    public void failed(Throwable e, Object attachment) {
                        fail(e);
                    }
                    @Override
                    public void completed(Line result, Object attachment) {
                        mLine = result;
                        sendSeek();
                    }
                }, null);
            } catch (TelehashException e) {
                fail(e);
            }
        }
    }
    
    private void sendSeek() {
        Channel channel = mLine.openChannel(SEEK_TYPE, new ChannelHandler() {
            @Override
            public void handleError(Channel channel, Throwable error) {
                fail(error);
            }
            @Override
            public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
                parseResult(channelPacket);
            }
        });
        
        Map<String,Object> fields = new HashMap<String,Object>();
        fields.put("seek", mTargetHashName.asHex());
        try {
            channel.send(null, fields, false);
        } catch (TelehashException e) {
            fail(e);
            return;
        }
    }
    
    private void parseResult(ChannelPacket channelPacket) {
        Object seeObject = channelPacket.get("see");
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
            Endpoint endpoint;
            try {
                endpoint = mTelehash.getNetwork().parseEndpoint(
                        parts[1], Integer.parseInt(parts[2])
                );
                Node node = new Node(hashName, endpoint);
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
