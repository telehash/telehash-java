package org.telehash.crypto.set2a;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.telehash.core.Identity;
import org.telehash.core.LineIdentifier;
import org.telehash.core.Node;
import org.telehash.core.OpenPacket;
import org.telehash.core.TelehashException;
import org.telehash.core.UnwrappedOpenPacket;
import org.telehash.core.Util;
import org.telehash.crypto.CipherSet;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.crypto.LineKeyPair;
import org.telehash.crypto.LinePrivateKey;
import org.telehash.crypto.LinePublicKey;
import org.telehash.network.Path;

public class CipherSet2aImpl implements CipherSet {
	
	private Crypto mCrypto;
	
    // elliptic curve settings
    private ECNamedCurveParameterSpec mECNamedCurveParameterSpec;
    private ECKeyPairGenerator mECGenerator = new ECKeyPairGenerator();
    private ECDomainParameters mECDomainParameters;
    private ECKeyGenerationParameters mECKeyGenerationParameters;
    
    private SecureRandom mRandom = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    };
    
    public CipherSet2aImpl(Crypto crypto) {
    	mCrypto = crypto;
    	
        // initialize elliptic curve parameters and generator
        mECNamedCurveParameterSpec =
                ECNamedCurveTable.getParameterSpec("prime256v1");
        mECGenerator = new ECKeyPairGenerator();
        mECDomainParameters =
                new ECDomainParameters(
                        mECNamedCurveParameterSpec.getCurve(),
                        mECNamedCurveParameterSpec.getG(),
                        mECNamedCurveParameterSpec.getN()
                );
        mECKeyGenerationParameters =
                new ECKeyGenerationParameters(mECDomainParameters, mRandom);        
        mECGenerator.init(mECKeyGenerationParameters);
    }

    /**
     * Generate a fresh identity (i.e., RSA public and private key pair) for a
     * newly provisioned Telehash node.
     * 
     * @return The new identity.
     * @throws TelehashException 
     */
    @Override
    public Identity generateIdentity() throws TelehashException {
        // generate a 2048 bit key pair
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(
                new RSAKeyGenerationParameters(
                    new BigInteger("10001", 16),//publicExponent
                    // TODO: see warning in getRandomBytes()!
                    new SecureRandom(),
                    2048, // key length
                    80    // prime certainty
                )
            );
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        
        AsymmetricKeyParameter publicKey = keyPair.getPublic();
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        if (! (privateKey instanceof RSAPrivateCrtKeyParameters)) {
            throw new TelehashException("generated key is not an RSA private key.");
        }
        return new Identity(
                new HashNameKeyPairImpl(
                        new HashNamePublicKeyImpl(publicKey),
                        new HashNamePrivateKeyImpl((RSAPrivateCrtKeyParameters)privateKey)
                )
        );
    }
    
    /**
     * Create a new HashNameKeyPair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created HashNameKeyPair object.
     */
    @Override
    public HashNameKeyPair createHashNameKeyPair(HashNamePublicKey publicKey, HashNamePrivateKey privateKey) {
        return new HashNameKeyPairImpl((HashNamePublicKeyImpl)publicKey, (HashNamePrivateKeyImpl)privateKey);
    }
    
    /**
     * Decode a public key.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the buffer cannot be parsed.
     */
    @Override
    public HashNamePublicKey decodeHashNamePublicKey(byte[] buffer) throws TelehashException {
        return new HashNamePublicKeyImpl(buffer);
    }
    
    /**
     * Decode a private key.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the buffer cannot be parsed.
     */
    @Override
    public HashNamePrivateKey decodeHashNamePrivateKey(byte[] buffer) throws TelehashException {
        return new HashNamePrivateKeyImpl(buffer);
    }
    
    /**
     * Decode an ANSI X9.63-encoded elliptic curve public key.
     * 
     * @param buffer The byte buffer containing the ANSI X9.63-encoded key.
     * @return The decoded public key.
     * @throws TelehashException If the ANSI X9.63 buffer cannot be parsed.
     */
    @Override
    public LinePublicKey decodeLinePublicKey(byte[] buffer) throws TelehashException {
        return new LinePublicKeyImpl(buffer, mECDomainParameters);
    }

    /**
     * Decode a byte-encoded elliptic curve private key.
     * 
     * @param buffer The byte buffer containing the encoded key.
     * @return The decoded private key.
     * @throws TelehashException If the byte buffer cannot be parsed.
     */
    @Override
    public LinePrivateKey decodeLinePrivateKey(byte[] buffer) throws TelehashException {
        return new LinePrivateKeyImpl(buffer, mECDomainParameters);
    }

    /**
     * Create a new elliptic curve key pair from the provided public and private key.
     * @param privateKey
     * @param publicKey
     * @return The newly created key pair.
     */
    @Override
    public LineKeyPair createLineKeyPair(
            LinePublicKey publicKey,
            LinePrivateKey privateKey
    ) throws TelehashException {
        return new LineKeyPairImpl((LinePublicKeyImpl)publicKey, (LinePrivateKeyImpl)privateKey);
    }

    /**
     * Generate a fresh elliptic curve key pair
     */
    @Override
    public LineKeyPair generateLineKeyPair() throws TelehashException {
        AsymmetricCipherKeyPair keyPair = mECGenerator.generateKeyPair();
        
        AsymmetricKeyParameter publicKey = keyPair.getPublic();
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        if (! (publicKey instanceof ECPublicKeyParameters)) {
            throw new TelehashException("generated key is not an elliptic curve public key.");
        }
        if (! (privateKey instanceof ECPrivateKeyParameters)) {
            throw new TelehashException("generated key is not an elliptic curve private key.");
        }
        return new LineKeyPairImpl(
                (ECPublicKeyParameters)publicKey,
                (ECPrivateKeyParameters)privateKey
        );
    }
    
    @Override
    public UnwrappedOpenPacket unwrapOpenPacket(
    		HashNamePrivateKey hashNamePrivateKey,
    		byte[] iv,
    		byte[] encryptedSignature,
    		byte[] openParameter,
    		byte[] encryptedInnerPacket,
    		Path path
    ) throws TelehashException {
        // Using your hashname private key, decrypt the open param,
        // extracting the line public key of the sender
        byte[] linePublicKeyBuffer =
                mCrypto.decryptRSAOAEP(hashNamePrivateKey, openParameter);
        LinePublicKey linePublicKey = decodeLinePublicKey(linePublicKeyBuffer);
        
        // Hash the ECC public key with SHA-256 to generate the AES key
        byte[] innerPacketKey =
        		mCrypto.sha256Digest(linePublicKeyBuffer);
        
        // Decrypt the inner packet using the generated key and IV value with
        // the AES-256-CTR algorithm.
        byte[] innerPacketBuffer =
        		mCrypto.decryptAES256CTR(encryptedInnerPacket, iv, innerPacketKey);
        
    	UnwrappedOpenPacket unwrappedOpenPacket = new UnwrappedOpenPacket();
    	unwrappedOpenPacket.iv = iv;
    	unwrappedOpenPacket.encryptedSignature = encryptedSignature;
    	unwrappedOpenPacket.encryptedInnerPacket = encryptedInnerPacket;
    	unwrappedOpenPacket.path = path;
        unwrappedOpenPacket.linePublicKeyBuffer = linePublicKeyBuffer;
        unwrappedOpenPacket.linePublicKey = linePublicKey;
        unwrappedOpenPacket.innerPacketKey = innerPacketKey;
        unwrappedOpenPacket.innerPacketBuffer = innerPacketBuffer;
        return unwrappedOpenPacket;
    }
    
    public OpenPacket verifyOpenPacket(
    		UnwrappedOpenPacket unwrappedOpenPacket,
    		byte[] destination,
    		byte[] lineIdentifierBytes,
    		LineIdentifier lineIdentifier,
    		long openTime,
    		byte[] innerPacketBody
    ) throws TelehashException {
                
        // Extract the hashname public key of the sender from the inner
        // packet BODY (binary encoded format).
        HashNamePublicKey senderHashNamePublicKey =
        		mCrypto.decodeHashNamePublicKey(innerPacketBody);
        
        // SHA-256 hash the hashname public key to derive the sender's hashname
        Node sourceNode = new Node(senderHashNamePublicKey, unwrappedOpenPacket.path);
        
        // Verify the "at" timestamp is newer than any other "open"
        // requests received from the sender.
        // TODO: "newer than any other open..." <-- should be handled at higher level
        
        // SHA-256 hash the ECC public key with the 16 bytes derived from the
        // inner line hex value to generate a new AES key
        byte[] signatureKey = mCrypto.sha256Digest(
                Util.concatenateByteArrays(
                		unwrappedOpenPacket.linePublicKeyBuffer,
                		lineIdentifierBytes
                )
        );
        
        // Decrypt the outer packet sig value using AES-256-CTR with the key
        // from #8 and the same IV value as #3.
        byte[] signature = mCrypto.decryptAES256CTR(
        		unwrappedOpenPacket.encryptedSignature,
        		unwrappedOpenPacket.iv,
        		signatureKey
        );
        
        // Using the hashname public key of the sender, verify the signature
        // (decrypted in #9) of the original (encrypted) form of the inner
        // packet
        if (! mCrypto.verifyRSA(
        		senderHashNamePublicKey,
        		unwrappedOpenPacket.encryptedInnerPacket,
        		signature)) {
            throw new TelehashException("signature verification failed.");
        }
        
        // If an open packet has not already been sent to this hashname, do so
        // by creating one following the steps above
        // TODO: handle at higher level
        
        // After sending your own open packet in response, you may now generate
        // a line shared secret using the received and sent line public keys and
        // Elliptic Curve Diffie-Hellman (ECDH).
        // TODO: handle at higher level

        return new OpenPacket(
        		sourceNode,
        		unwrappedOpenPacket.linePublicKey,
        		openTime,
        		lineIdentifier
        );
    }
}
