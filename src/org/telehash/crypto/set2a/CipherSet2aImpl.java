package org.telehash.crypto.set2a;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

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
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONStringer;
import org.telehash.core.HashName;
import org.telehash.core.Identity;
import org.telehash.core.LineIdentifier;
import org.telehash.core.Node;
import org.telehash.core.OpenPacket;
import org.telehash.core.Packet;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.UnwrappedOpenPacket;
import org.telehash.core.Util;
import org.telehash.core.Packet.JsonAndBody;
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
    
    @Override
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
    
    @Override
    public OpenPacket parseOpenPacket(
            Telehash telehash,
            JSONObject json,
            byte[] body,
            Path path
    ) throws TelehashException {
        // extract required JSON values
        String ivString = json.getString(OpenPacket.IV_KEY);
        Util.assertNotNull(ivString);
        byte[] iv = Util.hexToBytes(ivString);
        Util.assertBufferSize(iv, OpenPacket.IV_SIZE);
        String sigString = json.getString(OpenPacket.SIG_KEY);
        Util.assertNotNull(sigString);
        byte[] encryptedSignature = Util.base64Decode(sigString);
        Util.assertNotNull(encryptedSignature);
        String openString = json.getString(OpenPacket.OPEN_KEY);
        Util.assertNotNull(openString);
        byte[] openParameter = Util.base64Decode(openString);
        Util.assertNotNull(openParameter);

        // unwrap the open packet using the relevant cipher set
        UnwrappedOpenPacket unwrappedOpenPacket =
        		unwrapOpenPacket(
        				telehash.getIdentity().getPrivateKey(),
        				iv,
        				encryptedSignature,
        				openParameter,
        				body,
        				path
        		);
        
        // extract required JSON values from the inner packet
        JsonAndBody innerPacket = Packet.splitPacket(unwrappedOpenPacket.innerPacketBuffer);
        long openTime = innerPacket.json.getLong(OpenPacket.OPEN_TIME_KEY);
        String destinationString = innerPacket.json.getString(OpenPacket.DESTINATION_KEY);
        Util.assertNotNull(destinationString);
        byte[] destination = Util.hexToBytes(destinationString);
        Util.assertBufferSize(destination, HashName.SIZE);
        String lineIdentifierString = innerPacket.json.getString(OpenPacket.LINE_IDENTIFIER_KEY);
        Util.assertNotNull(lineIdentifierString);
        byte[] lineIdentifierBytes = Util.hexToBytes(lineIdentifierString);
        Util.assertBufferSize(lineIdentifierBytes, OpenPacket.LINE_IDENTIFIER_SIZE);
        LineIdentifier lineIdentifier = new LineIdentifier(lineIdentifierBytes);
        
        // Verify the "to" value of the inner packet matches your hashname
        if (! Arrays.equals(destination, telehash.getIdentity().getHashName().getBytes())) {
            throw new TelehashException("received packet not destined for this identity.");
        }
        
        // verify and assemble the parsed open packet using the relevant cipher set.
        return verifyOpenPacket(
        		unwrappedOpenPacket,
        		destination,
        		lineIdentifierBytes,
        		lineIdentifier,
        		openTime,
        		innerPacket.body
        );
    }
    
    /**
     * Pre-render the open packet.
     * 
     * @throws TelehashException
     */
    public void preRenderOpenPacket(OpenPacket open) throws TelehashException {
        Crypto crypto = Telehash.get().getCrypto();
        
        // generate a random IV
        open.setPreRenderedIV(crypto.getRandomBytes(OpenPacket.IV_SIZE));
        
        // note the current time.
        // This is a "local" timestamp -- the remote node will not
        // interpret this as the number of milliseconds since 1970,
        // but merely as an ever-incrementing value where a greater
        // value indicates a newer open packet.  This timestamp should
        // be the time of line key generation.
        open.setOpenTime(System.currentTimeMillis());
        
        // generate the line key pair
        LineKeyPair lineKeyPair = crypto.generateLineKeyPair();
        open.setLinePublicKey(lineKeyPair.getPublicKey());
        open.setLinePrivateKey(lineKeyPair.getPrivateKey());

        // generate the "open" parameter by encrypting the public line
        // key with the recipient's hashname public key.
        open.setPreRenderedOpenParameter(crypto.encryptRSAOAEP(
        		open.getDestinationNode().getPublicKey(),
        		open.getLinePublicKey().getEncoded()
        ));
    }
    
    /**
     * Render the open packet into its final form.
     * 
     * This version of the method allows the caller to pass in values for
     * certain otherwise calculated fields, allowing for deterministic open
     * packet creation suitable for unit tests.
     * 
     * @param open The open packet object.
     * @param iv
     *            The initialization vector to use for this open packet.
     * @param openParameter
     *            The "open" parameter -- the public line key encrypted
     *            with the recipient's hashname public key.
     * @return The rendered open packet as a byte array.
     * @throws TelehashException
     */
    @Override
    public byte[] renderOpenPacket(
    		OpenPacket open,
    		Identity identity,
            byte[] iv,
            byte[] openParameter
    ) throws TelehashException {
        byte[] encodedLinePublicKey = open.getLinePublicKey().getEncoded();
        
        // SHA-256 hash the public line key to form the encryption
        // key for the inner packet
        byte[] innerPacketAESKey = mCrypto.sha256Digest(encodedLinePublicKey);
        
		// Form the inner packet containing a current timestamp "at", line
		// identifier, recipient hashname, and family (if you have such a
		// value). Your own hashname public key is the packet BODY in
		// the encoded binary format.
        byte[] innerPacket;
        try {
            innerPacket = new JSONStringer()
                .object()
                .key(OpenPacket.OPEN_TIME_KEY)
                .value(open.getOpenTime())
                .key(OpenPacket.DESTINATION_KEY)
                .value(open.getDestinationNode().getHashName().asHex())
                .key(OpenPacket.LINE_IDENTIFIER_KEY)
                .value(open.getLineIdentifier().asHex())
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
                identity.getPublicKey().getEncoded()
        );

        // Encrypt the inner packet using the hashed line public key from #4
        // and the IV you generated at #2 using AES-256-CTR.
        byte[] encryptedInnerPacket = mCrypto.encryptAES256CTR(innerPacket, iv, innerPacketAESKey);

        // Create a signature from the encrypted inner packet using your own hashname
        // keypair, a SHA 256 digest, and PKCSv1.5 padding
        byte[] signature = mCrypto.signRSA(identity.getPrivateKey(), encryptedInnerPacket);
        
        // Encrypt the signature using a new AES-256-CTR cipher with the same IV
        // and a new SHA-256 key hashed from the line public key + the
        // line value (16 bytes from #5), then base64 encode the result as the
        // value for the sig param.
        byte[] signatureKey = mCrypto.sha256Digest(
                Util.concatenateByteArrays(encodedLinePublicKey, open.getLineIdentifier().getBytes())
        ); 
        byte[] encryptedSignature =
                mCrypto.encryptAES256CTR(signature, iv, signatureKey);

        // Form the outer packet containing the open type, open param, the
        // generated iv, and the sig value.
        byte[] outerPacket;
        try {
            outerPacket = new JSONStringer()
                .object()
                .key(Packet.TYPE_KEY)
                .value(OpenPacket.OPEN_TYPE)
                .key(OpenPacket.IV_KEY)
                .value(Util.bytesToHex(iv))
                .key(OpenPacket.SIG_KEY)
                .value(Util.base64Encode(encryptedSignature))
                .key(OpenPacket.OPEN_KEY)
                .value(Util.base64Encode(openParameter))
                .endObject()
                .toString()
                .getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new TelehashException(e);
        } catch (JSONException e) {
            throw new TelehashException(e);
        }
        
        byte[] lengthPrefix = new byte[Packet.LENGTH_PREFIX_SIZE];
        lengthPrefix[0] = (byte)((outerPacket.length >> 8) & 0xFF);
        lengthPrefix[1] = (byte)(outerPacket.length & 0xFF);
        byte[] buffer = Util.concatenateByteArrays(
                lengthPrefix,
                outerPacket,
                encryptedInnerPacket
        );

        return buffer;
    }
}
