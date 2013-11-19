package org.telehash.network.impl;

import java.net.InetAddress;

import org.telehash.network.Endpoint;

public class InetEndpoint implements Endpoint {
    private InetAddress mAddress;
    private int mPort;

    public InetEndpoint(InetAddress address, int port) {
        mAddress = address;
        mPort = port;
    }
    
    public InetAddress getAddress() {
        return mAddress;
    }
    public int getPort() {
        return mPort;
    }
}
