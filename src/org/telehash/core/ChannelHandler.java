package org.telehash.core;

public interface ChannelHandler {
    void handleError(Throwable error);
    void handleIncoming(ChannelPacket channelPacket);
}
