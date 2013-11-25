package org.telehash.core;

import org.telehash.crypto.Crypto;
import org.telehash.crypto.ECKeyPair;
import org.telehash.crypto.RSAPublicKey;

public class PacketFactory {

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

        // generate the elliptic curve key pair
        ECKeyPair ellipticCurveKeyPair = Util.getCryptoInstance().generateECKeyPair();
        ellipticCurveKeyPair.getPublicKey().getEncoded();
        
        // SHA-256 hash the public elliptic key to form the encryption key for the inner packet
        //byte[] aesKey = crypto.sha256Digest(ellipticCurveKeyPair.getPublic().getEncoded());
        
        // encrypt the ECC public key with our RSA private key.
        
        // TODO: 
        // 1. implement KeyPair Crypto.generateECCKeyPair()
        // 2. implement byte[] Crypto.encryptRSA(PublicKey key, byte[]);
        // 3. implement Crypto.random()
        // 4. implement base64encode(), base64decode().
        // 5. create open parameter
        // 6. create iv
        // 7. create sig
        // 8. record relevant information in a PendingOpen.
        
        return new Packet();
    }

}
