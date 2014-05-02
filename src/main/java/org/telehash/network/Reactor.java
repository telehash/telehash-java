package org.telehash.network;

import java.io.IOException;

public interface Reactor {
    void setDatagramHandler(DatagramHandler datagramHandler);
    void setMessageHandler(MessageHandler messageHandler);
    void start() throws IOException;
    void stop();
    void close() throws IOException;
    void wakeup();
    void select(long timeout) throws IOException;
    void sendDatagram(Datagram datagram);
    void sendMessage(Message message);
}
