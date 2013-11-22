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
        /*
        try {
            ASN1Object o = ASN1Object.fromByteArray(destinationPublicKey.getEncoded());
            System.out.println("ASN1Object="+o);
            ASN1Sequence s = (ASN1Sequence)o;
            System.out.println("ASN1Sequence="+s);
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(s);
            System.out.println("subjectPublicKeyInfo="+subjectPublicKeyInfo);
            
            System.out.println("destination PK DER:  "+Util.bytesToHex(destinationPublicKeyDer));
            System.out.println("SPKI DER encoded:    "+Util.bytesToHex(subjectPublicKeyInfo.getDEREncoded()));
            System.out.println("SPKI encoded:        "+Util.bytesToHex(subjectPublicKeyInfo.getEncoded()));
            System.out.println("SPKI.PK.DER encoded: "+
                    Util.bytesToHex(subjectPublicKeyInfo.getPublicKey().getDEREncoded())
            );
            System.out.println("SPKI.PK encoded:     "+
                    Util.bytesToHex(subjectPublicKeyInfo.getPublicKey().getEncoded())
            );
            System.out.println();
            System.out.println("key.getEncoded():");
            System.out.println(ASN1Dump.dumpAsString(o));
            System.out.println("SPKI DER:");
            System.out.println(ASN1Dump.dumpAsString(
                    ASN1Object.fromByteArray(
                            subjectPublicKeyInfo.getDEREncoded())
                    )
            );
            System.out.println("SPKI.PK DER:");
            System.out.println(ASN1Dump.dumpAsString(
                    ASN1Object.fromByteArray(
                            subjectPublicKeyInfo.getPublicKey().getDEREncoded())
                    )
            );
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        */
        /*
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
                    (ASN1Sequence)ASN1Object.fromByteArray(
                            destinationPublicKey.getEncoded()
                    )
            );
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }*/
        
        // generate a random IV
        byte[] iv = crypto.getRandomBytes(16);
        
        // generate a random line identifier
        byte[] lineIdentifier = crypto.getRandomBytes(16);

        // generate the elliptic curve key pair
        ECKeyPair ellipticCurveKeyPair = Util.getCryptoInstance().generateECCKeyPair();
        ellipticCurveKeyPair.getPublicKey().getUncompressedKey();
        
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
