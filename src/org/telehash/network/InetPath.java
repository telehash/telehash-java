package org.telehash.network;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.json.JSONObject;
import org.telehash.core.TelehashException;

public class InetPath extends Path {
    private static final String IP_ADDRESS_KEY = "ip";
    private static final String PORT_KEY = "port";
    
    private InetAddress mAddress;
    private int mPort;

    public InetPath(InetAddress address, int port) {
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
    
    @Override
    public String getType() {
        if (mAddress instanceof Inet4Address) {
            return IPV4_TYPE;
        } else if (mAddress instanceof Inet6Address) {
            return IPV6_TYPE;
        } else {
            return "ip-unknown";
        }
    }
    
    @Override
    public JSONObject toJSONObject() {
        JSONObject json = new JSONObject();
        json.put(TYPE_KEY, getType());
        json.put(IP_ADDRESS_KEY, mAddress.getHostAddress());
        json.put(PORT_KEY, mPort);
        return json;
    }
    
    public String toString() {
        return getType()+":" + mAddress.getHostAddress() + "/" + mPort;
    }
    
    static public InetPath parsePath(JSONObject path) throws TelehashException {
        if (path == null) {
            return null;
        }
        String type = path.getString(TYPE_KEY);
        if (type == null || type.isEmpty()) {
            return null;
        }

        String ipString = (String) path.get(IP_ADDRESS_KEY);
        if (ipString == null || ipString.isEmpty()) {
            return null;
        }
        int port = ((Number)path.get(PORT_KEY)).intValue();
        InetAddress address;
        try {
            // TODO: is this safe?
            address = InetAddress.getByName(ipString);
        } catch (UnknownHostException e) {
            throw new TelehashException(e);
        }

        // validation
        if ( (! type.equals(IPV4_TYPE)) && (! type.equals(IPV6_TYPE)) ) {
            throw new TelehashException("unknown internet path type \""+type+"\".");
        }
        if ( (!(address instanceof Inet4Address)) || (!(address instanceof Inet6Address)) ) {
            throw new TelehashException("path does not represent a valid address");
        }
        if ( (address instanceof Inet4Address && (! type.equals(IPV4_TYPE))) ||
             (address instanceof Inet6Address && (! type.equals(IPV6_TYPE))) ) {
            throw new TelehashException(
                    "address \""+ipString+"\" is not suitable for type \""+type+"\"."
            );
        }
        
        return new InetPath(address, port);
    }
}
