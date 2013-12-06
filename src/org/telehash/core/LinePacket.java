package org.telehash.core;

import java.io.UnsupportedEncodingException;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONStringer;
import org.telehash.crypto.Crypto;
import org.telehash.network.Endpoint;

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
    
    private static final String LINE_TYPE = "line";
    
    private static final String LINE_IDENTIFIER_KEY = "line";
    private static final String IV_KEY = "iv";
    
    private static final int IV_SIZE = 16;
    private static final int LINE_IDENTIFIER_SIZE = 16;
    
    static {
        Packet.registerPacketType(LINE_TYPE, LinePacket.class);
    }
    
    private Line mLine;
    private byte[] mBody;

    public LinePacket(Line line) {
        mLine = line;
    }
    
    public LinePacket(Line line, byte[] body) {
        mLine = line;
        mBody = body;
    }
    
    // accessor methods
    
    public void setLine(Line line) {
        mLine = line;
    }
    public Line getLine() {
        return mLine;
    }
    
    public void setBody(byte[] body) {
        mBody = body;
    }
    public byte[] getBody() {
        return mBody;
    }    
    
    /**
     * Render the open packet into its final form.
     * 
     * @return The rendered open packet as a byte array.
     */
    public byte[] render() throws TelehashException {
        Crypto crypto = Util.getCryptoInstance();
        
        if (mBody == null) {
            mBody = new byte[0];
        }
        
        // generate a random IV
        byte[] iv = crypto.getRandomBytes(IV_SIZE);
        
        // encrypt body
        byte[] encryptedBody = crypto.encryptAES256CTR(mBody, iv, mLine.getEncryptionKey());
        
        // Form the inner packet containing a current timestamp at, line
        // identifier, recipient hashname, and family (if you have such a
        // value). Your own RSA public key is the packet BODY in the binary DER
        // format.
        byte[] packet;
        try {
            packet = new JSONStringer()
                .object()
                .key(TYPE_KEY)
                .value(LINE_TYPE)
                .key(LINE_IDENTIFIER_KEY)
                .value(Util.bytesToHex(mLine.getOutgoingLineIdentifier()))
                .key(IV_KEY)
                .value(Util.bytesToHex(iv))
                .endObject()
                .toString()
                .getBytes("UTF-8");
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
                encryptedBody
        );

        return packet;
    }
    
    public static LinePacket parse(
            Telehash telehash,
            JSONObject json,
            byte[] body,
            Endpoint endpoint
    ) throws TelehashException {
        Crypto crypto = telehash.getCrypto();
        
        // extract required JSON values
        String ivString = json.getString(IV_KEY);
        assertNotNull(ivString);
        byte[] iv = Util.hexToBytes(ivString);
        assertBufferSize(iv, IV_SIZE);
        String lineIdentifierString = json.getString(LINE_IDENTIFIER_KEY);
        assertNotNull(lineIdentifierString);
        byte[] lineIdentifier = Util.hexToBytes(lineIdentifierString);
        assertBufferSize(lineIdentifier, LINE_IDENTIFIER_SIZE);
        
        // lookup the line
        Line line = telehash.getSwitch().getLine(lineIdentifier);
        if (line == null) {
            throw new TelehashException("unknown line id");
        }

        // decrypt the body
        byte[] decryptedBody = crypto.decryptAES256CTR(body, iv, line.getDecryptionKey());
        return new LinePacket(line, decryptedBody);
    }
}
