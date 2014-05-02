package org.telehash.core;

import org.telehash.json.JSONException;
import org.telehash.json.JSONObject;
import org.telehash.crypto.CipherSet;
import org.telehash.network.Path;

import java.io.UnsupportedEncodingException;

public abstract class Packet {

    private static final int MINIMUM_PACKET_LENGTH = 2;
    private static final int HEADER_START_POSITION = 2;
    private static final int MINIMUM_HEADER_LENGTH = 0;
    private static final int MAXIMUM_HEADER_LENGTH = 64*1024;
    private static final int OPEN_HEADER_LENGTH = 1;
    private static final int LINE_HEADER_LENGTH = 0;
    public static final int LENGTH_PREFIX_SIZE = 2;
    public static final String TYPE_KEY = "type";

    private static enum OuterPacketType {
        OPEN, LINE
    }

    protected PeerNode mSourceNode;
    protected PeerNode mDestinationNode;

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

    public void setSourceNode(PeerNode sourceNode) {
        mSourceNode = sourceNode;
    }
    public PeerNode getSourceNode() {
        return mSourceNode;
    }

    public void setDestinationNode(PeerNode destinationNode) {
        mDestinationNode = destinationNode;
    }
    public PeerNode getDestinationNode() {
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
        OuterPacketType type = null;
        if (splitPacket.json != null) {
            throw new TelehashException("JSON found in outer packet header");
        }
        if (splitPacket.headerLength == OPEN_HEADER_LENGTH) {
            CipherSet cipherSet = telehash.getCrypto().getCipherSet(
                    new CipherSetIdentifier(splitPacket.singleByteHeader)
            );
            if (cipherSet == null) {
                throw new TelehashException(
                        "unsupported open cipher set: "+splitPacket.singleByteHeader
                );
            }
            type = OuterPacketType.OPEN;
        } else if (splitPacket.headerLength == LINE_HEADER_LENGTH) {
            type = OuterPacketType.LINE;
        } else {
            throw new TelehashException("unknown packet configuration");
        }

        // dispatch to the parse routine of the appropriate subclass.
        switch (type) {
        case OPEN:
            return OpenPacket.parse(telehash, splitPacket, sourcePath);
        case LINE:
            return LinePacket.parse(telehash, splitPacket, sourcePath);
        default:
            throw new TelehashException("unknown outer packet type");
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
