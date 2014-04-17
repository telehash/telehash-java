package org.telehash.core;

import org.telehash.crypto.Crypto;
import org.telehash.network.Path;

/**
 * A Telehash "line" packet is used to exchange data between two Telehash nodes
 * that have established a shared secret via open packets.
 *
 * <p>
 * A line packet consists of the following components, in roughly the order in
 * which they should be unpacked:
 * </p>
 *
 * <ol>
 * <li>The line identifier</li>
 * <li>A random initialization vector (IV) used for the AES encryption of the inner packet.</li>
 * <li>An embedded "inner packet" containing arbitrary data.  This inner packet
 * is AES-CTR encrypted using a key derived from the SHA-256 hash of shared secret,
 * the outgoing line id, and the incoming line id.</li>
 * </ol>
 */
public class LinePacket extends Packet {

    private static final String LINE_IDENTIFIER_KEY = "line";
    private static final String IV_KEY = "iv";
    private static final int IV_SIZE = 16;
    public static final String LINE_TYPE = "line";

    static {
        Packet.registerPacketType(LINE_TYPE, LinePacket.class);
    }

    private Line mLine;
    private ChannelPacket mChannelPacket;

    public LinePacket(Line line) {
        mLine = line;
        mDestinationNode = line.getRemoteNode();
    }

    public LinePacket(Line line, ChannelPacket channelPacket) {
        mLine = line;
        mChannelPacket = channelPacket;
        // TODO: this is wrong if we are parsing an incoming packet --
        //       line.getRemoteNode() should be the *source* not the *destination*!
        mDestinationNode = line.getRemoteNode();
    }

    // accessor methods

    public void setLine(Line line) {
        mLine = line;
    }
    public Line getLine() {
        return mLine;
    }

    public void setChannelPacket(ChannelPacket channelPacket) {
        mChannelPacket = channelPacket;
    }
    public ChannelPacket getChannelPacket() {
        return mChannelPacket;
    }

    /**
     * Render the open packet into its final form.
     *
     * @return The rendered open packet as a byte array.
     */
    @Override
    public byte[] render() throws TelehashException {
        Crypto crypto = Telehash.get().getCrypto();

        // serialize the channel packet
        if (mChannelPacket == null) {
            mChannelPacket = new ChannelPacket();
        }
        byte[] channelPlaintext = mChannelPacket.render();

        // regard the line id
        byte[] lineBytes = mLine.getOutgoingLineIdentifier().getBytes();
        if (lineBytes.length != LineIdentifier.SIZE) {
            throw new TelehashException("line id must be exactly 16 bytes");
        }

        // cipherset processing of inner packet
        byte[] inner = crypto.getCipherSet().renderLineInnerPacket(mLine, channelPlaintext);

        byte[] headerLengthPrefix = new byte[] {0,0};
        byte[] packet = Util.concatenateByteArrays(headerLengthPrefix, lineBytes, inner);
        return packet;
    }

    public static LinePacket parse(
            Telehash telehash,
            SplitPacket splitPacket,
            Path path
    ) throws TelehashException {
        Crypto crypto = telehash.getCrypto();

        if (splitPacket.headerLength != 0 ||
                splitPacket.json != null ||
                splitPacket.body == null ||
                splitPacket.body.length < LineIdentifier.SIZE
        ) {
            throw new TelehashException("invalid line packet format");
        }

        // extract the line id
        byte[] lineIdBytes = new byte[LineIdentifier.SIZE];
        System.arraycopy(splitPacket.body, 0, lineIdBytes, 0, LineIdentifier.SIZE);
        LineIdentifier lineIdentifier = new LineIdentifier(lineIdBytes);

        // confirm that the line id is valid
        Line line = telehash.getSwitch().getLineManager().getLine(lineIdentifier);
        if (line == null) {
            throw new TelehashException("unknown line id: "+lineIdentifier);
        }

        // extract the inner packet
        int innerPacketSize = splitPacket.body.length - LineIdentifier.SIZE;
        byte[] innerPacket = new byte[innerPacketSize];
        System.arraycopy(splitPacket.body, LineIdentifier.SIZE, innerPacket, 0, innerPacketSize);

        // cipherset processing of inner packet
        byte[] channelPlaintext = crypto.getCipherSet().parseLineInnerPacket(line, innerPacket);

        // parse the embedded channel packet
        ChannelPacket channelPacket = ChannelPacket.parse(telehash, channelPlaintext, path);

        return new LinePacket(line, channelPacket);
    }

    @Override
    public String toString() {
        String s = "LINE["+mLine+"]";
        if (mSourceNode != null) {
            s += " <"+mSourceNode;
        }
        if (mDestinationNode != null) {
            s += " <"+mDestinationNode;
        }
        return s;
    }
}
