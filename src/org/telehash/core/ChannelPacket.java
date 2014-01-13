package org.telehash.core;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONStringer;
import org.json.JSONWriter;
import org.telehash.network.Path;

public class ChannelPacket extends Packet {
    private static final String CHANNEL_IDENTIFIER_KEY = "c";
    private static final String END_KEY = "end";
    private static final String ERROR_KEY = "err";
    private static final String CUSTOM_FIELDS_KEY = "_";
    
    private static final int CHANNEL_IDENTIFIER_SIZE = 16;

    private ChannelIdentifier mChannelIdentifier;
    private String mType;
    private boolean mEnd = false;
    private String mError;
    private Map<String,Object> mFields = new HashMap<String,Object>();
    private JSONObject mCustomFields;
    private byte[] mBody;
    
    public ChannelPacket() {
        
    }
    
    private ChannelPacket(
            ChannelIdentifier channelIdentifer,
            String type,
            boolean end,
            String error,
            JSONObject customFields
    ) {
        mChannelIdentifier = channelIdentifer;
        mType = type;
        mEnd = end;
        mError = error;
        mCustomFields = customFields;
    }

    public void setChannelIdentifier(ChannelIdentifier channelIdentifier) {
        mChannelIdentifier = channelIdentifier;
    }
    
    public ChannelIdentifier getChannelIdentifier() {
        return mChannelIdentifier;
    }
    
    public void setType(String type) {
        mType = type;
    }
    
    public String getType() {
        return mType;
    }
    
    public void setEnd(boolean end) {
        mEnd = end;
    }
    
    public boolean isEnd() {
        return mEnd;
    }
    
    public void setError(String error) {
        mError = error;
    }
    
    public String getError() {
        return mError;
    }
    
    public void setCustomFields(JSONObject customFields) {
        mCustomFields = customFields;
    }
    
    public JSONObject getCustomFields() {
        return mCustomFields;
    }
    
    public void setBody(byte[] body) {
        mBody = body;
    }
    
    public byte[] getBody() {
        return mBody;
    }
    
    public void put(String key, Object value) {
        mFields.put(key, value);
    }
    
    public Object get(String key) {
        return mFields.get(key);
    }
    
    @Override
    public byte[] render() throws TelehashException {
        if (mBody == null) {
            mBody = new byte[0];
        }
        
        byte[] packet;
        try {
            JSONWriter json = new JSONStringer().object();
            json = json.key(CHANNEL_IDENTIFIER_KEY).value(mChannelIdentifier.asHex());
            if (mType != null) {
                json = json.key(TYPE_KEY).value(mType);
            }
            if (mEnd) {
                json = json.key(END_KEY).value(true);
            }
            if (mError != null) {
                json = json.key(ERROR_KEY).value(mError);
            }
            for (Map.Entry<String,Object> entry : mFields.entrySet()) {
                json = json.key(entry.getKey()).value(entry.getValue());
            }
            if (mCustomFields != null) {
                json = json
                    .key(CUSTOM_FIELDS_KEY)
                    .value(mCustomFields);
            }
            packet = json.endObject().toString().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new TelehashException(e);
        } catch (JSONException e) {
            throw new TelehashException(e);
        }
        packet = Util.concatenateByteArrays(
                new byte[] {
                        (byte)((packet.length >> 8) & 0xFF),
                        (byte)(packet.length & 0xFF)
                },
                packet,
                mBody
        );

        return packet;
    }

    public static ChannelPacket parse(
            Telehash telehash,
            byte[] packetBuffer,
            Path path
    ) throws TelehashException {
        JsonAndBody jsonAndBody = splitPacket(packetBuffer);
        return parse(telehash, jsonAndBody.json, jsonAndBody.body, path);
    }
    
    public static ChannelPacket parse(
            Telehash telehash,
            JSONObject json,
            byte[] body,
            Path path
    ) throws TelehashException {
        // extract required JSON values
        String channelIdentifierString = json.getString(CHANNEL_IDENTIFIER_KEY);
        assertNotNull(channelIdentifierString);
        byte[] channelIdentifierBytes = Util.hexToBytes(channelIdentifierString);
        assertBufferSize(channelIdentifierBytes, CHANNEL_IDENTIFIER_SIZE);
        ChannelIdentifier channelIdentifier = new ChannelIdentifier(channelIdentifierBytes);
        
        String type = null;
        if (json.has(TYPE_KEY)) {
            type = json.getString(TYPE_KEY);
        }
        
        boolean end;
        if (json.has(END_KEY) && json.getBoolean(END_KEY)) {
            end = json.getBoolean(END_KEY);
        } else {
            end = false;
        }
        
        String error = null;
        if (json.has(ERROR_KEY)) {
            json.getString(ERROR_KEY);
        }
        
        JSONObject customFields = null;
        if (json.has(CUSTOM_FIELDS_KEY)) {
            customFields = json.getJSONObject(CUSTOM_FIELDS_KEY);
        }

        ChannelPacket channelPacket =
                new ChannelPacket(channelIdentifier, type, end, error, customFields);
        channelPacket.setBody(body);

        // extract all other (channel-type-specific) JSON values
        @SuppressWarnings("unchecked")
        Iterator<String> iterator = json.keys();
        while (iterator.hasNext()) {
            String key = iterator.next();
            if (!(  key.equals(CHANNEL_IDENTIFIER_KEY) ||
                    key.equals(TYPE_KEY) ||
                    key.equals(END_KEY) ||
                    key.equals(ERROR_KEY) ||
                    key.equals(CUSTOM_FIELDS_KEY))) {
                Object value = json.get(key);
                channelPacket.put(key, value);
            }
        }
        
        return channelPacket;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("channelpacket[id="+mChannelIdentifier+"/");
        if (mType != null) {
            sb.append("type="+mType+"/");
        }
        if (mEnd) {
            sb.append("end/");
        }
        if (mError != null) {
            sb.append("error="+mError+"/");
        }
        for (Map.Entry<String, Object> entry : mFields.entrySet()) {
            sb.append(entry.getKey()+"="+entry.getValue()+"/");
        }
        if (mBody != null) {
            sb.append("bodylen="+mBody.length);
        }
        sb.append("]");
        return sb.toString();
    }
}
