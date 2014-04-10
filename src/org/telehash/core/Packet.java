package org.telehash.core;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;
import org.telehash.network.Path;

public abstract class Packet {
    
    private static final int MINIMUM_PACKET_LENGTH = 2;
    private static final int JSON_START_POSITION = 2;
    private static final int MINIMUM_JSON_LENGTH = 0;
    private static final int MAXIMUM_JSON_LENGTH = 64*1024;
    private static final String PARSE_METHOD_NAME = "parse";
    public static final int LENGTH_PREFIX_SIZE = 2;
    public static final String TYPE_KEY = "type";
    
    private static Map<String,Method> sTypeParseMap =
            new HashMap<String,Method>(); 
    
    protected Node mSourceNode;
    protected Node mDestinationNode;

    public static final class JsonAndBody {
        public JsonAndBody(JSONObject json, byte[] body) {
            this.json = json;
            this.body = body;
        }
        public JSONObject json;
        public byte[] body;
    }
    
    public void setSourceNode(Node sourceNode) {
        mSourceNode = sourceNode;
    }
    public Node getSourceNode() {
        return mSourceNode;
    }

    public void setDestinationNode(Node destinationNode) {
        mDestinationNode = destinationNode;
    }
    public Node getDestinationNode() {
        return mDestinationNode;
    }
    
    /**
     * Render the packet into its final form.
     * 
     * @return A byte array of the rendered packet.
     * @throws TelehashException
     */
    public abstract byte[] render() throws TelehashException;
    
    /**
     * Parse the provided byte buffer into a packet object. This method will
     * examine the "type" header, and dispatch to the parse method of the
     * appropriate subclass.
     * 
     * @param telehash The Telehash context.
     * @param buffer The buffer to parse.
     * @param sourcePath The path from which this packet was received.
     * @return
     * @throws TelehashException
     */
    public static Packet parse(
            Telehash telehash,
            byte[] buffer,
            Path sourcePath
    ) throws TelehashException {
        // split the packet into the JSON header and the body.
        JsonAndBody jsonAndBody = splitPacket(buffer);
        if (jsonAndBody == null) {
            // null packet received
            return null;
        }

        // examine the "type" header
        String type = jsonAndBody.json.getString(TYPE_KEY);
        if (type == null || type.isEmpty()) {
            throw new TelehashException("invalid type string");
        }
        if (! sTypeParseMap.containsKey(type)) {
            throw new TelehashException("unknown packet type: \""+type+"\"");
        }
        
        // dispatch to the parse routine of the appropriate subclass.
        try {
            return (Packet) sTypeParseMap.get(type).invoke(
                    null, telehash, jsonAndBody.json, jsonAndBody.body, sourcePath
            );
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("cannot invoke parse method.", e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("cannot invoke parse method.", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause != null && cause instanceof TelehashException) {
                throw ((TelehashException)cause);
            } else {
                throw new RuntimeException("exception in parse method.", e);
            }
        }
    }

    public static JsonAndBody splitPacket(byte[] buffer) throws TelehashException {
        if (buffer.length <= MINIMUM_PACKET_LENGTH) {
            // this can happen if we receive "null" packets
            return null;
        }
        
        int jsonLength = ((buffer[0]&0xFF)<<8) | (buffer[1]&0xFF);
        if (jsonLength < MINIMUM_JSON_LENGTH || jsonLength > MAXIMUM_JSON_LENGTH) {
            throw new TelehashException("invalid json length");
        }

        JSONObject json;
        try {
            json = new JSONObject(new String(buffer, JSON_START_POSITION, jsonLength, "UTF-8"));
        } catch (JSONException e) {
            throw new TelehashException(e);
        } catch (UnsupportedEncodingException e) {
            throw new TelehashException(e);
        }
        
        int bodyLength = buffer.length - jsonLength - JSON_START_POSITION;
        byte[] body = new byte[bodyLength];
        System.arraycopy(buffer, JSON_START_POSITION+jsonLength, body, 0, bodyLength);
        
        return new JsonAndBody(json, body);
    }
    
    protected static void registerPacketType(
            String typeName,
            Class<? extends Packet> packetClass
    ) {
        Method method;
        try {
            method = packetClass.getMethod(
                    PARSE_METHOD_NAME,
                    Telehash.class,
                    JSONObject.class,
                    byte[].class,
                    Path.class
            );
        } catch (NoSuchMethodException e) {
            throw new RuntimeException("cannot find parse method in class.", e);
        }
        sTypeParseMap.put(typeName, method);
    }
    
    protected static final void assertNotNull(Object o) throws TelehashException {
        if (o == null) {
            throw new TelehashException("null value unexpectedly encountered");
        }
    }
    
    protected static final void assertBufferSize(
            byte[] buffer,
            int length
    ) throws TelehashException {
        if (buffer == null) {
            throw new TelehashException("null value unexpectedly encountered");            
        }
        if (buffer.length != length) {
            throw new TelehashException("invalid buffer size");
        }
    }
}
