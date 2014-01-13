package org.telehash.test.network;

import java.util.HashMap;
import java.util.Map;

import org.telehash.network.Datagram;
import org.telehash.network.DatagramHandler;
import org.telehash.network.InetPath;
import org.telehash.network.Path;

public class Router {

    private Map<InetPath,DatagramHandler> mNetworkMap =
            new HashMap<InetPath,DatagramHandler>();

    public void registerNetwork(FakeNetworkImpl network) {
        mNetworkMap.put((InetPath)network.getPath(), network);
    }
    
    public void sendDatagram(Datagram datagram) {
        InetPath destination = new InetPath(((InetPath)datagram.getDestination()).getAddress(), 0);
        DatagramHandler handler = mNetworkMap.get(destination);
        if (handler != null) {
            handler.handleDatagram(datagram);
        }
    }
}
