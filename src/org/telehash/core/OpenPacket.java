package org.telehash.core;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONStringer;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.LineKeyPair;
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
    
    private static final String OPEN_TYPE = "open";
    
    private static final String IV_KEY = "iv";
    private static final String SIG_KEY = "sig";
    private static final String OPEN_KEY = "open";
    private static final String OPEN_TIME_KEY = "at";
    private static final String DESTINATION_KEY = "to";
    private static final String LINE_IDENTIFIER_KEY = "line";
    
    private static final int IV_SIZE = 16;
    private static final int LINE_IDENTIFIER_SIZE = 16;
    private static final int HASHNAME_SIZE = 32;
    
    static {
        Packet.registerPacketType(OPEN_TYPE, OpenPacket.class);
    }
    
    private Identity mIdentity;
    private HashNamePublicKey mSenderHashNamePublicKey;
    private LinePublicKey mLinePublicKey;
    private LinePrivateKey mLinePrivateKey;
    private long mOpenTime;
    private LineIdentifier mLineIdentifier;

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

    private boolean mPreRendered = false;
    private byte[] mPreRenderedIV;
    private byte[] mPreRenderedOpenParameter;
    
    public void preRender() throws TelehashException {
        mPreRendered = true;

        Crypto crypto = Telehash.get().getCrypto();
        
        // generate a random IV
        mPreRenderedIV = crypto.getRandomBytes(IV_SIZE);
        
        // note the current time.
        // This is a "local" timestamp -- the remote node will not
        // interpret this as the number of milliseconds since 1970,
        // but merely as an ever-incrementing value where a greater
        // value indicates a newer open packet.  This timestamp should
        // be the time of line key generation.
        mOpenTime = System.currentTimeMillis();
        
        // generate the line key pair
        LineKeyPair lineKeyPair = crypto.generateLineKeyPair();
        mLinePublicKey = lineKeyPair.getPublicKey();
        mLinePrivateKey = lineKeyPair.getPrivateKey();

        // generate the "open" parameter by encrypting the public line
        // key with the recipient's hashname public key.
        mPreRenderedOpenParameter = crypto.encryptRSAOAEP(
                mDestinationNode.getPublicKey(),
                mLinePublicKey.getEncoded()
        );
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
        Crypto crypto = Telehash.get().getCrypto();

        byte[] encodedECPublicKey = mLinePublicKey.getEncoded();
        
        // SHA-256 hash the public line key to form the encryption
        // key for the inner packet
        byte[] innerPacketAESKey = crypto.sha256Digest(encodedECPublicKey);
        
		// Form the inner packet containing a current timestamp at, line
		// identifier, recipient hashname, and family (if you have such a
		// value). Your own hashname public key is the packet BODY in
		// the encoded binary format.
        byte[] innerPacket;
        try {
            innerPacket = new JSONStringer()
                .object()
                .key(OPEN_TIME_KEY)
                .value(mOpenTime)
                .key(DESTINATION_KEY)
                .value(mDestinationNode.getHashName().asHex())
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
        innerPacket = Util.concatenateByteArrays(
                new byte[] {
                        (byte)((innerPacket.length >> 8) & 0xFF),
                        (byte)(innerPacket.length & 0xFF)
                },
                innerPacket,
                mIdentity.getPublicKey().getEncoded()
        );

        // Encrypt the inner packet using the hashed line public key from #4
        // and the IV you generated at #2 using AES-256-CTR.
        byte[] encryptedInnerPacket = crypto.encryptAES256CTR(innerPacket, iv, innerPacketAESKey);

        // Create a signature from the encrypted inner packet using your own hashname
        // keypair, a SHA 256 digest, and PKCSv1.5 padding
        byte[] signature = crypto.signRSA(mIdentity.getPrivateKey(), encryptedInnerPacket);
        
        // Encrypt the signature using a new AES-256-CTR cipher with the same IV
        // and a new SHA-256 key hashed from the line public key + the
        // line value (16 bytes from #5), then base64 encode the result as the
        // value for the sig param.
        byte[] signatureKey = crypto.sha256Digest(
                Util.concatenateByteArrays(encodedECPublicKey, mLineIdentifier.getBytes())
        ); 
        byte[] encryptedSignature =
                crypto.encryptAES256CTR(signature, iv, signatureKey);

        // Form the outer packet containing the open type, open param, the
        // generated iv, and the sig value.
        byte[] outerPacket;
        try {
            outerPacket = new JSONStringer()
                .object()
                .key(TYPE_KEY)
                .value(OPEN_TYPE)
                .key(IV_KEY)
                .value(Util.bytesToHex(iv))
                .key(SIG_KEY)
                .value(Util.base64Encode(encryptedSignature))
                .key(OPEN_KEY)
                .value(Util.base64Encode(openParameter))
                .endObject()
                .toString()
                .getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new TelehashException(e);
        } catch (JSONException e) {
            throw new TelehashException(e);
        }
        
        byte[] lengthPrefix = new byte[LENGTH_PREFIX_SIZE];
        lengthPrefix[0] = (byte)((outerPacket.length >> 8) & 0xFF);
        lengthPrefix[1] = (byte)(outerPacket.length & 0xFF);
        byte[] packet = Util.concatenateByteArrays(
                lengthPrefix,
                outerPacket,
                encryptedInnerPacket
        );

        return packet;
    }
    
    public static OpenPacket parse(
            Telehash telehash,
            JSONObject json,
            byte[] body,
            Path path
    ) throws TelehashException {
        Crypto crypto = telehash.getCrypto();
        
        // extract required JSON values
        String ivString = json.getString(IV_KEY);
        assertNotNull(ivString);
        byte[] iv = Util.hexToBytes(ivString);
        assertBufferSize(iv, IV_SIZE);
        String sigString = json.getString(SIG_KEY);
        assertNotNull(sigString);
        byte[] encryptedSignature = Util.base64Decode(sigString);
        assertNotNull(encryptedSignature);
        String openString = json.getString(OPEN_KEY);
        assertNotNull(openString);
        byte[] openParameter = Util.base64Decode(openString);
        assertNotNull(openParameter);

        // unwrap the open packet using the relevant cipher set
        UnwrappedOpenPacket unwrappedOpenPacket =
        		telehash.getCrypto().getCipherSet().unwrapOpenPacket(
        				telehash.getIdentity().getPrivateKey(),
        				iv,
        				encryptedSignature,
        				openParameter,
        				body,
        				path
        		);
        
        // extract required JSON values from the inner packet
        JsonAndBody innerPacket = splitPacket(unwrappedOpenPacket.innerPacketBuffer);
        long openTime = innerPacket.json.getLong(OPEN_TIME_KEY);
        String destinationString = innerPacket.json.getString(DESTINATION_KEY);
        assertNotNull(destinationString);
        byte[] destination = Util.hexToBytes(destinationString);
        assertBufferSize(destination, HASHNAME_SIZE);
        String lineIdentifierString = innerPacket.json.getString(LINE_IDENTIFIER_KEY);
        assertNotNull(lineIdentifierString);
        byte[] lineIdentifierBytes = Util.hexToBytes(lineIdentifierString);
        assertBufferSize(lineIdentifierBytes, LINE_IDENTIFIER_SIZE);
        LineIdentifier lineIdentifier = new LineIdentifier(lineIdentifierBytes);
        
        // Verify the "to" value of the inner packet matches your hashname
        if (! Arrays.equals(destination, telehash.getIdentity().getHashName().getBytes())) {
            throw new TelehashException("received packet not destined for this identity.");
        }
        
        // verify and assemble the parsed open packet using the relevant cipher set.
        return telehash.getCrypto().getCipherSet().verifyOpenPacket(
        		unwrappedOpenPacket,
        		destination,
        		lineIdentifierBytes,
        		lineIdentifier,
        		openTime,
        		innerPacket.body
        );
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
