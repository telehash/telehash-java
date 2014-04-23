package org.telehash.dht;

import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.Log;
import org.telehash.core.PeerNode;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;

import java.util.HashMap;
import java.util.Map;

public class Link {

    private DHT mDHT;
    private PeerNode mNode;
    private Channel mChannel = null;

    public Link(DHT dht, PeerNode node) {
        mDHT = dht;
        mNode = node;
    }

    public Link(DHT dht, Channel channel) {
        mDHT = dht;
        mChannel = channel;
        mNode = channel.getRemoteNode();
    }

    public void init() {
        Telehash.get().getSwitch().openChannelNow(mNode, DHT.LINK_TYPE, new ChannelHandler() {
            @Override
            public void handleError(Channel channel, Throwable error) {
                Log.e("DHT: problem linking to seed "+mNode+":", error);
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

    private void handleIncoming(ChannelPacket channelPacket) {
        Log.i("DHT XXX: handleIncoming() channel: "+mChannel);
        Log.i("DHT: incoming link packet: "+channelPacket);

        if (channelPacket.isEnd()) {
            close();
        }
    }

    private void send() {
        Map<String,Object> linkMsg = new HashMap<String,Object>();
        linkMsg.put(DHT.SEED_KEY, true);
        try {
            mChannel.send(null, linkMsg, false);
        } catch (TelehashException e) {
            Log.e("DHT: problem sending initial link message: ", e);
        }
    }

    public void close() {
        mDHT.delinkSeed(this);
        mDHT.getNodeTracker().removeNode(mNode);
    }
}
