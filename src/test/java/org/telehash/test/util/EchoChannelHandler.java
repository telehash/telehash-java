package org.telehash.test.util;

import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.Log;
import org.telehash.core.TelehashException;

public class EchoChannelHandler implements ChannelHandler {

    public static final String TYPE = "echo";

    @Override
    public void handleOpen(Channel channel) {
        Log.i("echo channel handler: channel opened");
    }

    @Override
    public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
        Log.i("echo channel handler: received "+channelPacket.getBody().length+" bytes.");
        try {
            channel.send(channelPacket.getBody());
        } catch (TelehashException e) {
            Log.e("echo channel handler: error sending response",  e);
        }
    }

    @Override
    public void handleError(Channel channel, Throwable error) {
        Log.i("echo channel handler: channel error", error);
    }
}
