package org.telehash.core;

public interface ChannelHandler {
    void handleError(Channel channel, Throwable error);
    void handleIncoming(Channel channel, ChannelPacket channelPacket);
    void handleOpen(Channel channel);
}
