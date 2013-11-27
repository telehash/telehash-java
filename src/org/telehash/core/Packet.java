package org.telehash.core;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;

public abstract class Packet {
    
    private static final int MINIMUM_PACKET_LENGTH = 4;
    private static final int JSON_START_POSITION = 2;
    private static final int MINIMUM_JSON_LENGTH = 2;
    private static final int MAXIMUM_JSON_LENGTH = 64*1024;
    private static final String PARSE_METHOD_NAME = "parse";
    protected static final int LENGTH_PREFIX_SIZE = 2;
    protected static final String TYPE_KEY = "type";
    
    private static Map<String,Method> sTypeParseMap =
            new HashMap<String,Method>(); 

    protected static final class JsonAndBody {
        public JsonAndBody(JSONObject json, byte[] body) {
            this.json = json;
            this.body = body;
        }
        public JSONObject json;
        public byte[] body;
    }
    
    /**
     * Render the packet into its final form.
     * 
     * @return A byte array of the rendered packet.
     * @throws TelehashException
     */
    public abstract byte[] render() throws TelehashException;
    
    public static Packet parse(Telehash telehash, byte[] buffer) throws TelehashException {
        JsonAndBody jsonAndBody = splitPacket(buffer);

        String type = jsonAndBody.json.getString(TYPE_KEY);
        if (type == null || type.isEmpty()) {
            throw new TelehashException("invalid type string");
        }
        if (! sTypeParseMap.containsKey(type)) {
            throw new TelehashException("unknown packet type");
        }
        
        try {
            return (Packet) sTypeParseMap.get(type).invoke(
                    null, telehash, jsonAndBody.json, jsonAndBody.body
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

    protected static JsonAndBody splitPacket(byte[] buffer) throws TelehashException {
        if (buffer.length < MINIMUM_PACKET_LENGTH) {
            throw new TelehashException("packet too small");
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
                    byte[].class
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
