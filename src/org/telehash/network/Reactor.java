package org.telehash.network;

import java.io.IOException;

public interface Reactor {
    void setDatagramHandler(DatagramHandler datagramHandler);
    void start() throws IOException;
    void stop();
    void close() throws IOException;
    void wakeup();
    void select(long timeout) throws IOException;
    void sendPacket(Datagram datagram);
}
