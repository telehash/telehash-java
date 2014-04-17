package org.telehash.core;

import org.json.JSONException;
import org.json.JSONObject;
import org.telehash.crypto.CipherSet;
import org.telehash.network.Path;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public abstract class Packet {

    private static final int MINIMUM_PACKET_LENGTH = 2;
    private static final int HEADER_START_POSITION = 2;
    private static final int MINIMUM_HEADER_LENGTH = 0;
    private static final int MAXIMUM_HEADER_LENGTH = 64*1024;
    private static final int OPEN_HEADER_LENGTH = 1;
    private static final int LINE_HEADER_LENGTH = 0;
    private static final String PARSE_METHOD_NAME = "parse";
    public static final int LENGTH_PREFIX_SIZE = 2;
    public static final String TYPE_KEY = "type";

    private static Map<String,Method> sTypeParseMap =
            new HashMap<String,Method>();

    protected Node mSourceNode;
    protected Node mDestinationNode;

    public static final class SplitPacket {
        public SplitPacket(int headerLength, short singleByteHeader, JSONObject json, byte[] body) {
            this.headerLength = headerLength;
            this.singleByteHeader = singleByteHeader;
            this.json = json;
            this.body = body;
        }
        public int headerLength;
        public short singleByteHeader;
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
        SplitPacket splitPacket = splitPacket(buffer);
        if (splitPacket == null) {
            // null packet received
            return null;
        }

        // determine the packet type
        String type;
        if (splitPacket.json == null) {
            // TODO: remove all uses of OPEN_TYPE and LINE_TYPE, as these don't actually
            // use a type field any more.
            if (splitPacket.headerLength == OPEN_HEADER_LENGTH) {
                CipherSet cipherSet = telehash.getCrypto().getCipherSet(
                        new CipherSetIdentifier(splitPacket.singleByteHeader)
                );
                if (cipherSet == null) {
                    throw new TelehashException(
                            "unsupported open cipher set: "+splitPacket.singleByteHeader
                    );
                }
                type = OpenPacket.OPEN_TYPE;
            } else if (splitPacket.headerLength == LINE_HEADER_LENGTH) {
                type = LinePacket.LINE_TYPE;
            } else {
                throw new TelehashException("unknown packet configuration");
            }
        } else {
            // examine the "type" header
            type = splitPacket.json.getString(TYPE_KEY);
            if (type == null || type.isEmpty()) {
                throw new TelehashException("invalid type string");
            }
            if (! sTypeParseMap.containsKey(type)) {
                throw new TelehashException("unknown packet type: \""+type+"\"");
            }
        }

        // dispatch to the parse routine of the appropriate subclass.
        try {
            return (Packet) sTypeParseMap.get(type).invoke(
                    null, telehash, splitPacket, sourcePath
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

    public static SplitPacket splitPacket(byte[] buffer) throws TelehashException {
        if (buffer.length <= MINIMUM_PACKET_LENGTH) {
            // this can happen if we receive "null" packets
            return null;
        }

        int headerLength = ((buffer[0]&0xFF)<<8) | (buffer[1]&0xFF);
        if (headerLength < MINIMUM_HEADER_LENGTH || headerLength > MAXIMUM_HEADER_LENGTH) {
            throw new TelehashException("invalid json length");
        }

        JSONObject json;
        short singleByteHeader;
        if (headerLength == 0) {
            json = null;
            singleByteHeader = 0x00;
        } else if (headerLength == 1) {
            json = null;
            singleByteHeader = buffer[HEADER_START_POSITION];
        } else {
            singleByteHeader = 0x00;
            try {
                json = new JSONObject(
                        new String(buffer, HEADER_START_POSITION, headerLength, "UTF-8")
                );
            } catch (JSONException e) {
                throw new TelehashException(e);
            } catch (UnsupportedEncodingException e) {
                throw new TelehashException(e);
            }
        }

        int bodyLength = buffer.length - headerLength - HEADER_START_POSITION;
        byte[] body = new byte[bodyLength];
        System.arraycopy(buffer, HEADER_START_POSITION+headerLength, body, 0, bodyLength);

        return new SplitPacket(headerLength, singleByteHeader, json, body);
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
                    SplitPacket.class,
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
