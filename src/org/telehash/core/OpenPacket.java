package org.telehash.core;

import org.json.JSONException;
import org.json.JSONStringer;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.crypto.LinePrivateKey;
import org.telehash.crypto.LinePublicKey;
import org.telehash.network.Path;

import java.io.UnsupportedEncodingException;

/**
 * A Telehash "open" packet is used to establish a line between two Telehash
 * nodes.
 *
 * <p>
 * The open packet consists of the following components, in roughly the order in
 * which they should be unpacked:
 * </p>
 *
 * <ol>
 * <li>The public key from a line key pair uniquely generated for this open.
 * This key is encrypted using the destination's hashname public key.</li>
 * <li>A random initialization vector (IV) used for the AES encryption of other
 * components within this packet.</li>
 * <li>An embedded "inner packet" containing the time, destination hash name,
 * line identifier, and the hashname public key of the initiator. This inner
 * packet is AES-CTR encrypted using the SHA-256 hash of the generated line
 * public key, and attached to the outer packet as the body.</li>
 * <li>An signature of the encrypted inner packet, proving the authenticity of
 * the sender. The signature itself is encrypted using the SHA-256 hash of the
 * line public key and the line identifier.</li>
 * </ol>
 */
public class OpenPacket extends Packet {

    public static final String OPEN_TYPE = "open";

    public static final String SIG_KEY = "sig";
    public static final String OPEN_KEY = "open";
    public static final String OPEN_TIME_KEY = "at";
    public static final String DESTINATION_KEY = "to";
    public static final String LINE_IDENTIFIER_KEY = "line";

    public static final int IV_SIZE = 16;
    public static final int LINE_IDENTIFIER_SIZE = 16;

    static {
        Packet.registerPacketType(OPEN_TYPE, OpenPacket.class);
    }

    private Identity mIdentity;
    private HashNamePublicKey mSenderHashNamePublicKey;
    private LinePublicKey mLinePublicKey;
    private LinePrivateKey mLinePrivateKey;

    // TODO: remove these in favor of an Inner object?
    private long mOpenTime;
    private LineIdentifier mLineIdentifier;

    private boolean mPreRendered = false;
    private byte[] mPreRenderedLineKeyCiphertext;

    public static class Inner {
        // TODO: "from" field
        public HashName mDestination;
        public long mOpenTime;
        public LineIdentifier mLineIdentifier;

        public Inner(HashName destination, long openTime, LineIdentifier lineIdentifier) {
            mDestination = destination;
            mOpenTime = openTime;
            mLineIdentifier = lineIdentifier;
        }

        public static Inner deserialize(SplitPacket innerPacket) throws TelehashException {
            long openTime = innerPacket.json.getLong(OpenPacket.OPEN_TIME_KEY);
            String destinationString = innerPacket.json.getString(OpenPacket.DESTINATION_KEY);
            Util.assertNotNull(destinationString);
            byte[] destinationBytes = Util.hexToBytes(destinationString);
            Util.assertBufferSize(destinationBytes, HashName.SIZE);
            HashName destination = new HashName(destinationBytes);
            String lineIdentifierString =
                    innerPacket.json.getString(OpenPacket.LINE_IDENTIFIER_KEY);
            Util.assertNotNull(lineIdentifierString);
            byte[] lineIdentifierBytes = Util.hexToBytes(lineIdentifierString);
            Util.assertBufferSize(lineIdentifierBytes, OpenPacket.LINE_IDENTIFIER_SIZE);
            LineIdentifier lineIdentifier = new LineIdentifier(lineIdentifierBytes);
            return new Inner(destination, openTime, lineIdentifier);
        }

        public byte[] serialize() throws TelehashException {
            byte[] innerPacketHeaders;
            try {
                innerPacketHeaders = new JSONStringer()
                    .object()
                    .key(OPEN_TIME_KEY)
                    .value(mOpenTime)
                    .key(DESTINATION_KEY)
                    .value(mDestination.asHex())
                    .key(LINE_IDENTIFIER_KEY)
                    .value(mLineIdentifier.asHex())
                    .endObject()
                    .toString()
                    .getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new TelehashException(e);
            } catch (JSONException e) {
                throw new TelehashException(e);
            }
            return innerPacketHeaders;
        }
    }

    public OpenPacket(Identity identity, Node destinationNode) {
        mIdentity = identity;
        mDestinationNode = destinationNode;
        mSenderHashNamePublicKey = identity.getPublicKey();

        if (destinationNode.getPublicKey() == null) {
            throw new IllegalArgumentException(
                    "attempt to open a line to a node with unknown public key"
            );
        }

        // generate a random line identifier
        mLineIdentifier = new LineIdentifier(
                Telehash.get().getCrypto().getRandomBytes(LINE_IDENTIFIER_SIZE)
        );
    }

    public OpenPacket(
            Node sourceNode,
            LinePublicKey linePublicKey,
            long openTime,
            LineIdentifier lineIdentifier
    ) {
        mSourceNode = sourceNode;
        mLinePublicKey = linePublicKey;
        mOpenTime = openTime;
        mLineIdentifier = lineIdentifier;
    }

    // accessor methods

    public void setSenderHashNamePublicKey(HashNamePublicKey senderHashNamePublicKey) {
        mSenderHashNamePublicKey = senderHashNamePublicKey;
    }
    public HashNamePublicKey getSenderHashNamePublicKey() {
        return mSenderHashNamePublicKey;
    }

    public void setLinePublicKey(LinePublicKey publicKey) {
        mLinePublicKey = publicKey;
    }
    public LinePublicKey getLinePublicKey() {
        return mLinePublicKey;
    }

    public void setLinePrivateKey(LinePrivateKey privateKey) {
        mLinePrivateKey = privateKey;
    }
    public LinePrivateKey getLinePrivateKey() {
        return mLinePrivateKey;
    }

    public void setOpenTime(long openTime) {
        mOpenTime = openTime;
    }
    public long getOpenTime() {
        return mOpenTime;
    }

    public void setLineIdentifier(LineIdentifier lineIdentifier) {
        mLineIdentifier = lineIdentifier;
    }
    public LineIdentifier getLineIdentifier() {
        return mLineIdentifier;
    }

    public void setPreRenderedLineKeyCiphertext(byte[] preRenderedLineKeyCiphertext) {
        mPreRenderedLineKeyCiphertext = preRenderedLineKeyCiphertext;
    }
    public byte[] getPreRenderedLineKeyCiphertext() {
        return mPreRenderedLineKeyCiphertext;
    }

    public void preRender() throws TelehashException {
        Telehash.get().getCrypto().getCipherSet().preRenderOpenPacket(this);
        mPreRendered = true;
    }

    /**
     * Render the open packet into its final form.
     *
     * @return The rendered open packet as a byte array.
     */
    @Override
    public byte[] render() throws TelehashException {
        if (mPreRendered == false) {
            preRender();
        }

        // perform further packet creation.
        return render(mPreRenderedLineKeyCiphertext);
    }

    /**
     * Render the open packet into its final form.
     *
     * This version of the method allows the caller to pass in values for
     * certain otherwise calculated fields, allowing for deterministic open
     * packet creation suitable for unit tests.
     *
     * @param lineKeyCiphertext
     *            The line key ciphertext -- the public line key encrypted
     *            with the recipient's hashname public key.
     * @return The rendered open packet as a byte array.
     * @throws TelehashException
     */
    public byte[] render(
            byte[] lineKeyCiphertext
    ) throws TelehashException {
        return Telehash.get().getCrypto().getCipherSet().renderOpenPacket(
                this,
                mIdentity,
                lineKeyCiphertext
        );
    }

    public static OpenPacket parse(
            Telehash telehash,
            SplitPacket splitPacket,
            Path path
    ) throws TelehashException {
        return Telehash.get().getCrypto().getCipherSet().parseOpenPacket(
                telehash,
                splitPacket,
                path
        );
    }

    @Override
    public String toString() {
        String s = "OPEN["+mLineIdentifier+"@"+mOpenTime+"]";
        if (mSourceNode != null) {
            s += " <"+mSourceNode;
        }
        if (mDestinationNode != null) {
            s += " <"+mDestinationNode;
        }
        return s;
    }
}
