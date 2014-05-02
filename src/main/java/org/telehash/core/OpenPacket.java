package org.telehash.core;

import org.telehash.json.JSONException;
import org.telehash.json.JSONObject;
import org.telehash.json.JSONStringer;
import org.telehash.crypto.CipherSet;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.crypto.LinePrivateKey;
import org.telehash.crypto.LinePublicKey;
import org.telehash.network.Path;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

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

    public static final String SIG_KEY = "sig";
    public static final String OPEN_KEY = "open";
    public static final String OPEN_TIME_KEY = "at";
    public static final String DESTINATION_KEY = "to";
    public static final String LINE_IDENTIFIER_KEY = "line";
    public static final String FROM_KEY = "from";

    public static final int IV_SIZE = 16;
    public static final int LINE_IDENTIFIER_SIZE = 16;

    private LocalNode mLocalNode;
    private HashNamePublicKey mSenderHashNamePublicKey;
    private LinePublicKey mLinePublicKey;
    private LinePrivateKey mLinePrivateKey;
    private CipherSet mCipherSet;

    // TODO: remove these in favor of an Inner object?
    private long mOpenTime;
    private LineIdentifier mLineIdentifier;

    private boolean mPreRendered = false;
    private byte[] mPreRenderedLineKeyCiphertext;

    public static class Inner {
        public HashName mDestination;
        public long mOpenTime;
        public LineIdentifier mLineIdentifier;
        public SortedMap<CipherSetIdentifier,byte[]> mFrom =
                new TreeMap<CipherSetIdentifier,byte[]>();

        public Inner(HashName destination, long openTime,
                LineIdentifier lineIdentifier,
                SortedMap<CipherSetIdentifier, byte[]> from) {
            mDestination = destination;
            mOpenTime = openTime;
            mLineIdentifier = lineIdentifier;
            if (from != null) {
                mFrom.putAll(from);
            }
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

            // parse the "from" fingerprints
            JSONObject from = innerPacket.json.getJSONObject(FROM_KEY);
            Iterator<?> fromIterator = from.keys();
            SortedMap<CipherSetIdentifier, byte[]> fingerprints =
                    new TreeMap<CipherSetIdentifier, byte[]>();
            while (fromIterator.hasNext()) {
                String key = (String)fromIterator.next();
                String value = from.getString(key);
                byte[] csidBuffer = Util.hexToBytes(key);
                if (csidBuffer == null || csidBuffer.length != 1 || csidBuffer[0] == 0) {
                    throw new TelehashException("invalid cipher set id in open.from");
                }
                CipherSetIdentifier csid = new CipherSetIdentifier(csidBuffer[0]);
                byte[] fingerprint = Util.hexToBytes(value);
                fingerprints.put(csid, fingerprint);
            }

            return new Inner(destination, openTime, lineIdentifier, fingerprints);
        }

        public byte[] serialize() throws TelehashException {
            byte[] innerPacketHeaders;
            try {
                JSONObject fromJson = new JSONObject();
                for (Map.Entry<CipherSetIdentifier,byte[]> entry : mFrom.entrySet()) {
                    fromJson.put(entry.getKey().asHex(), Util.bytesToHex(entry.getValue()));
                }
                innerPacketHeaders = new JSONStringer()
                    .object()
                    .key(OPEN_TIME_KEY)
                    .value(mOpenTime)
                    .key(FROM_KEY)
                    .value(fromJson)
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

    /**
     * Create an open packet for an outgoing open.
     *
     * @param localNode
     * @param destinationNode
     * @param csid
     */
    public OpenPacket(LocalNode localNode, PeerNode destinationNode, CipherSetIdentifier csid, LineIdentifier lineIdentifier) {
        mLocalNode = localNode;
        mDestinationNode = destinationNode;
        mSenderHashNamePublicKey = localNode.getPublicKey(csid);

        mCipherSet = Telehash.get().getCrypto().getCipherSet(csid);
        if (mCipherSet == null) {
            throw new IllegalArgumentException("unsupported cipher set id");
        }

        if (mSenderHashNamePublicKey == null) {
            throw new IllegalArgumentException("no public key for sender");
        }

        if (destinationNode.getActivePublicKey() == null) {
            throw new IllegalArgumentException(
                    "attempt to open a line to a node with unknown public key"
            );
        }

        mLineIdentifier = lineIdentifier;
    }

    /**
     * Create an open packet for an incoming open.
     *
     * @param localNode
     * @param destinationNode
     * @param csid
     */
    public OpenPacket(
            CipherSetIdentifier cipherSetIdentifier,
            PeerNode sourceNode,
            LinePublicKey linePublicKey,
            long openTime,
            LineIdentifier lineIdentifier
    ) {
        mCipherSet = Telehash.get().getCrypto().getCipherSet(cipherSetIdentifier);
        if (mCipherSet == null) {
            throw new IllegalArgumentException("unsupported cipher set id");
        }
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

    public CipherSet getCipherSet() {
        return mCipherSet;
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
        mCipherSet.preRenderOpenPacket(this);
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
        return mCipherSet.renderOpenPacket(
                this,
                mLocalNode,
                lineKeyCiphertext
        );
    }

    public static OpenPacket parse(
            Telehash telehash,
            SplitPacket splitPacket,
            Path path
    ) throws TelehashException {
        CipherSetIdentifier cipherSetIdentifier =
                new CipherSetIdentifier(splitPacket.singleByteHeader);
        CipherSet cipherSet = Telehash.get().getCrypto().getCipherSet(cipherSetIdentifier);
        if (cipherSet == null) {
            throw new TelehashException("unsupported cipher set id");
        }
        OpenPacket openPacket = cipherSet.parseOpenPacket(
                telehash,
                splitPacket,
                path
        );
        return openPacket;
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
