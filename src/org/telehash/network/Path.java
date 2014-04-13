package org.telehash.network;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.telehash.core.TelehashException;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.List;

public abstract class Path {
    public static final String IPV4_TYPE = "ipv4";
    public static final String IPV6_TYPE = "ipv6";
    public static final String TYPE_KEY = "type";

    public abstract String getType();
    public abstract JSONObject toJSONObject();

    static public Path parsePath(String json) throws TelehashException {
        JSONObject jsonObject;
        try {
            jsonObject = new JSONObject(json);
        } catch (JSONException e) {
            throw new TelehashException(e);
        }
        return parsePath(jsonObject);
    }

    static public Path parsePath(JSONObject path) throws TelehashException {
        if (path == null) {
            return null;
        }
        String type = path.getString("type");
        if (type == null) {
            return null;
        }
        if (type.equals(IPV4_TYPE) || type.equals(IPV6_TYPE)) {
            return InetPath.parsePath(path);
        } else {
            return null;
        }
    }

    static public List<Path> parsePathArray(JSONArray array) throws TelehashException {
        List<Path> paths = new ArrayList<Path>();
        if (array == null) {
            return null;
        }

        for (int i=0; i<array.length(); i++) {
            Object pathObject = array.get(i);
            if (! (pathObject instanceof JSONObject)) {
                continue;
            }
            JSONObject pathJson = (JSONObject)pathObject;
            Path path = Path.parsePath(pathJson);
            paths.add(path);
        }
        return paths;
    }

    /**
     * Convert a Java SocketAddress to a Path object.
     * @param socketAddress
     * @return The network path object.
     * @throws TelehashException
     */
    static public Path socketAddressToPath(SocketAddress socketAddress) {
        if (! (socketAddress instanceof InetSocketAddress)) {
            return null;
        }
        InetSocketAddress inetSocketAddress = (InetSocketAddress)socketAddress;
        return new InetPath(inetSocketAddress.getAddress(), inetSocketAddress.getPort());
    }

}
