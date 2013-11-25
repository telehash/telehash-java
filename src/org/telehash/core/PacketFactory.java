package org.telehash.core;

import java.io.UnsupportedEncodingException;

import org.json.JSONException;
import org.json.JSONStringer;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.ECKeyPair;
import org.telehash.crypto.RSAPublicKey;

public class PacketFactory {

    private Identity mIdentity;
    
    /**
     * Create a new packet factory for the specified identity.
     * 
     * @param identity The identity of the local node.
     */
    public PacketFactory(Identity identity) {
        mIdentity = identity;
    }
    
    /**
     * Construct an "open" packet to open a line to the specified destination node.
     * 
     * @param destination The destination node
     * @return The open packet
     */
    public Packet createOpenPacket(Node destination) throws TelehashException {
        Crypto crypto = Util.getCryptoInstance();

        // regard the destination node's RSA public key.
        // TODO: confirm the key is non-null... e.g. if we know the hashname but
        // not the full key?
        RSAPublicKey destinationPublicKey = destination.getPublicKey();
        System.out.println("destinationPublicKey="+destinationPublicKey);
        byte[] destinationPublicKeyDer = destinationPublicKey.getDEREncoded();
        System.out.println("destinationPublicKeyDer="+Util.bytesToHex(destinationPublicKeyDer));

        // generate a random IV
        byte[] iv = crypto.getRandomBytes(16);
        
        // generate a random line identifier
        byte[] lineIdentifier = crypto.getRandomBytes(16);

        // generate the elliptic curve key pair, based on the "nistp256" curve
        ECKeyPair ellipticCurveKeyPair = crypto.generateECKeyPair();
        byte[] encodedECPublicKey = ellipticCurveKeyPair.getPublicKey().getEncoded();
        
        // SHA-256 hash the public elliptic key to form the encryption
        // key for the inner packet
        byte[] innerPacketAESKey = crypto.sha256Digest(encodedECPublicKey);
        
        // Form the inner packet containing a current timestamp at, line
        // identifier, recipient hashname, and family (if you have such a
        // value). Your own RSA public key is the packet BODY in the binary DER
        // format.
        byte[] innerPacket;
        try {
            innerPacket = new JSONStringer()
                .object()
                .key("to")
                .value(Util.bytesToHex(destination.getHashName()))
                .key("at")
                .value(System.currentTimeMillis())
                .key("line")
                .value(Util.bytesToHex(lineIdentifier))
                .endObject()
                .toString()
                .getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new TelehashException(e);
        } catch (JSONException e) {
            throw new TelehashException(e);
        }

        // Encrypt the inner packet using the hashed public elliptic key from #4
        // and the IV you generated at #2 using AES-256-CTR.
        byte[] encryptedInnerPacket = crypto.encryptAES256CTR(innerPacket, iv, innerPacketAESKey);

        // Create a signature from the encrypted inner packet using your own RSA
        // keypair, a SHA 256 digest, and PKCSv1.5 padding
        byte[] signature = crypto.signRSA(mIdentity.getPrivateKey(), encryptedInnerPacket);
        
        //
        // Encrypt the signature using a new AES-256-CTR cipher with the same IV
        // and a new SHA-256 key hashed from the public elliptic key + the line
        // value (16 bytes from #5), then base64 encode the result as the value
        // for the sig param.
        
        // Create an open param, by encrypting the public elliptic curve key you
        // generated (in uncompressed form, aka ANSI X9.63) with the recipient's
        // RSA public key and OAEP padding.

        // Form the outer packet containing the open type, open param, the
        // generated iv, and the sig value.

        // If you have also received an open packet from the recipient hostname,
        // you may use it now to generate a line shared secret, using the ECC
        // public key they sent in their open packet and Elliptic Curve
        // Diffie-Hellman (ECDH).
        
        // TODO: 
        // X 1. implement KeyPair Crypto.generateECCKeyPair()
        // X 2. implement byte[] Crypto.encryptRSA(PublicKey key, byte[]);
        // X 3. implement Crypto.random()
        // 4. implement base64encode(), base64decode().
        // 5. create open parameter
        // 6. create iv
        // 7. create sig
        // 8. record relevant information in a PendingOpen.
        
        return new Packet();
    }

}
