package org.telehash.dht;

import org.json.JSONArray;
import org.json.JSONException;
import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.CounterTrigger;
import org.telehash.core.HashName;
import org.telehash.core.Log;
import org.telehash.core.Node;
import org.telehash.core.PeerNode;
import org.telehash.core.SeeNode;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Link {

    private static final long NANOSECONDS_IN_SECOND = 1000000000L;
    private static final long MINIMUM_SEND_TIME = 30*NANOSECONDS_IN_SECOND;
    private static final long MAXIMUM_SEND_TIME = 55*NANOSECONDS_IN_SECOND;
    private static final long LINK_TIMEOUT = 120*NANOSECONDS_IN_SECOND;

    public enum State {
        PENDING,
        ACTIVE,
        CLOSED
    };
    private State mState = State.PENDING;
    private NodeTracker mNodeTracker;
    private PeerNode mNode;
    private Channel mChannel = null;
    private long mLastSend = 0L;
    private long mLastReceive = 0L;
    private CounterTrigger mTrigger = null;

    /**
     * Open a new link to the specified peer.
     *
     * @param nodeTracker
     * @param node
     */
    public Link(NodeTracker nodeTracker, PeerNode node) {
        mNodeTracker = nodeTracker;
        mNode = node;

        Telehash.get().getSwitch().openChannelNow(mNode, DHT.LINK_TYPE, new ChannelHandler() {
            @Override
            public void handleError(Channel channel, Throwable error) {
                Log.e("DHT: problem linking to seed "+mNode+":", error);
                mState = State.CLOSED;
                mNodeTracker.onLinkClose(Link.this);
                if (mTrigger != null) {
                    mTrigger.signal();
                }
            }
            @Override
            public void handleIncoming(Channel channel,
                    ChannelPacket channelPacket) {
                Link.this.handleIncoming(channelPacket);
            }
            @Override
            public void handleOpen(Channel channel) {
                Link.this.mChannel = channel;
                Log.i("DHT XXX: link channel open: "+channel);
                send();
            }
        });
    }

    /**
     * Accept a new link from a peer.
     *
     * @param nodeTracker
     * @param channel
     * @param channelPacket
     */
    public Link(NodeTracker nodeTracker, Channel channel, ChannelPacket channelPacket) {
        mNodeTracker = nodeTracker;
        mChannel = channel;
        mNode = channel.getRemoteNode();
        handleIncoming(channelPacket);
    }

    public State getState() {
        return mState;
    }

    public PeerNode getNode() {
        return mNode;
    }

    public void setTrigger(CounterTrigger trigger) {
        mTrigger = trigger;
    }

    private void handleIncoming(ChannelPacket channelPacket) {
        Log.i("DHT: incoming link packet: "+channelPacket);
        mLastReceive = System.nanoTime();

        if (channelPacket.isEnd()) {
            close();
            return;
        }

        // TODO: handle the "seed" boolean
        channelPacket.get(DHT.SEED_KEY);

        if (mState != State.ACTIVE) {
            mState = State.ACTIVE;
            mNodeTracker.onLinkActive(this);
            if (mTrigger != null) {
                mTrigger.signal();
            }
        }

        // parse any provided see nodes, and submit them to the DHT.
        Object seeArray = channelPacket.get(DHT.SEE_KEY);
        if (seeArray != null) {
            Set<SeeNode> seeNodes;
            try {
                seeNodes = parseSee(seeArray, mChannel.getRemoteNode());
            } catch (TelehashException e) {
                Log.e("bad see object in link channel");
                return;
            }
            // submit seeNodes to DHT for possible inclusion in buckets.
            for (SeeNode node : seeNodes) {
                mNodeTracker.submitNode(node);
            }
        }

        // TODO: honor the "seed" boolean
        // TODO: regard "end" and "err".

        // submit the link peer to the node tracker
        //mNodeTracker.submitNode(channel.getRemoteNode());


        // respond in kind
        send();

        // TODO: if this is a keepalive, then respond in kind.
        // TODO: complete!
    }

    private void send() {
        if ((System.nanoTime()-mLastSend) < MINIMUM_SEND_TIME) {
            // too soon
            return;
        }
        Map<String,Object> linkMsg = new HashMap<String,Object>();
        linkMsg.put(DHT.SEED_KEY, true);
        try {
            mChannel.send(null, linkMsg, false);
            mLastSend = System.nanoTime();
        } catch (TelehashException e) {
            Log.e("DHT: problem sending link message: ", e);
        }
    }

    public void close() {
        mState = State.CLOSED;
        mNodeTracker.onLinkClose(this);
    }

    private static Set<SeeNode> parseSee(
            Object seeObject,
            PeerNode referringNode
    ) throws TelehashException {
        if (! (seeObject instanceof JSONArray)) {
            throw new TelehashException("'see' object not an array");
        }
        JSONArray seeNodes = (JSONArray)seeObject;

        Set<SeeNode> sees = new HashSet<SeeNode>(seeNodes.length());
        for (int i=0; i<seeNodes.length(); i++) {
            String seeString;
            try {
                seeString = seeNodes.getString(i);
            } catch (JSONException e) {
                throw new TelehashException(e);
            }
            sees.add(SeeNode.parse(referringNode, seeString));
        }
        return sees;
    }

    // Java identity

    @Override
    public boolean equals(Object other) {
        if (other instanceof Link && ((Link)other).mNode.equals(this.mNode)) {
            return true;
        } else if (other instanceof Node && ((Node)other).equals(this.mNode)) {
            return true;
        } else if (other instanceof HashName
                && ((HashName) other).equals(this.mNode.getHashName())) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return mNode.hashCode();
    }

    @Override
    public String toString() {
        return mNode.getHashName().getShortHash()+"/"+mState.name();
    }

}
