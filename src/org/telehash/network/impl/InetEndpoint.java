package org.telehash.network.impl;

import java.net.Inet4Address;
import java.net.Inet6Address;
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
    
    public String getAddressString() {
        return mAddress.getHostAddress();
    }
    
    public String getType() {
        if (mAddress instanceof Inet4Address) {
            return "ipv4";
        } else if (mAddress instanceof Inet6Address) {
            return "ipv6";
        } else {
            return "ip-unknown";
        }
    }
    
    public String toString() {
        return "inet:" + mAddress.getHostAddress() + "/" + mPort;
    }
}
