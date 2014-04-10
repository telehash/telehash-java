package org.telehash.core;

import org.json.JSONObject;
import org.telehash.crypto.LinePrivateKey;
import org.telehash.crypto.LinePublicKey;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.Path;

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
    
    public static final String IV_KEY = "iv";
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
    private long mOpenTime;
    private LineIdentifier mLineIdentifier;
    
    private boolean mPreRendered = false;
    private byte[] mPreRenderedIV;
    private byte[] mPreRenderedOpenParameter;

    public OpenPacket(Identity identity, Node destinationNode) {
        mIdentity = identity;
        mDestinationNode = destinationNode;
        mSenderHashNamePublicKey = identity.getPublicKey();
        
        if (destinationNode.getPublicKey() == null) {
            throw new IllegalArgumentException("attempt to open a line to a node with unknown public key");
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

    public void setPreRenderedIV(byte[] preRenderedIV) {
    	mPreRenderedIV = preRenderedIV;
    }
    public byte[] getPreRenderedIV() {
    	return mPreRenderedIV;
    }
    
    public void setPreRenderedOpenParameter(byte[] preRenderedOpenParameter) {
    	mPreRenderedOpenParameter = preRenderedOpenParameter;
    }
    public byte[] getPreRenderedOpenParameter() {
    	return mPreRenderedOpenParameter;
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
    public byte[] render() throws TelehashException {
        if (mPreRendered == false) {
            preRender();
        }

        // perform further packet creation.
        return render(mPreRenderedIV, mPreRenderedOpenParameter);
    }
    
    /**
     * Render the open packet into its final form.
     * 
     * This version of the method allows the caller to pass in values for
     * certain otherwise calculated fields, allowing for deterministic open
     * packet creation suitable for unit tests.
     * 
     * @param iv
     *            The initialization vector to use for this open packet.
     * @param openParameter
     *            The "open" parameter -- the public line key encrypted
     *            with the recipient's hashname public key.
     * @return The rendered open packet as a byte array.
     * @throws TelehashException
     */
    public byte[] render(
            byte[] iv,
            byte[] openParameter
    ) throws TelehashException {
		return Telehash.get().getCrypto().getCipherSet().renderOpenPacket(this, mIdentity, iv, openParameter);
    }
    
    public static OpenPacket parse(
            Telehash telehash,
            JSONObject json,
            byte[] body,
            Path path
    ) throws TelehashException {
    	return Telehash.get().getCrypto().getCipherSet().parseOpenPacket(telehash, json, body, path);
    }
    
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
