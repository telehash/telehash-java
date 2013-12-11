package org.telehash.storage.impl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.telehash.core.Identity;
import org.telehash.core.Node;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.RSAPrivateKey;
import org.telehash.crypto.RSAPublicKey;
import org.telehash.network.Endpoint;
import org.telehash.network.impl.InetEndpoint;
import org.telehash.storage.Storage;

/**
 * This class contains implementations for the storage functions needed by
 * Telehash.
 */
public class StorageImpl implements Storage {
    
    private static final String DEFAULT_IDENTITY_FILENAME_BASE = "telehash-identity";
    private static final String PRIVATE_KEY_FILENAME_SUFFIX = ".key";
    private static final String PUBLIC_KEY_FILENAME_SUFFIX = ".pub";

    /**
     * Read the local Telehash identity (RSA key pair) from files named using
     * the specified base filename.
     * 
     * @param identityBaseFilename
     *            The base filename, e.g. "identity".
     * @return The read and parsed Telehash identity.
     * @throws TelehashException
     *             If a problem happened while reading and parsing the identity.
     */
    public Identity readIdentity(String identityBaseFilename) throws TelehashException {
        String privateKeyFilename = identityBaseFilename + PRIVATE_KEY_FILENAME_SUFFIX;
        String publicKeyFilename = identityBaseFilename + PUBLIC_KEY_FILENAME_SUFFIX;
        
        // read keys
        RSAPrivateKey privateKey =
                Util.getCryptoInstance().readRSAPrivateKeyFromFile(privateKeyFilename);
        RSAPublicKey publicKey =
                Util.getCryptoInstance().readRSAPublicKeyFromFile(publicKeyFilename);
        return new Identity(Util.getCryptoInstance().createRSAKeyPair(publicKey, privateKey));        
    }

    /**
     * Read the local Telehash identity (RSA key pair) from files named using
     * the default base filename.
     * 
     * @return The read and parsed Telehash identity.
     * @throws TelehashException
     *             If a problem happened while reading and parsing the identity.
     */
    public Identity readIdentity() throws TelehashException {
        return readIdentity(DEFAULT_IDENTITY_FILENAME_BASE);
    }
    
    /**
     * Write the local Telehash identity (RSA key pair) into files named using
     * the specified base filename.
     * 
     * @param identity
     *            The identity to write.
     * @param identityBaseFilename
     *            The base filename, e.g. "identity".
     * @throws TelehashException
     *             If a problem happened while writing the identity.
     */
    public void writeIdentity(Identity identity, String identityBaseFilename)
            throws TelehashException {
        String privateKeyFilename = identityBaseFilename + PRIVATE_KEY_FILENAME_SUFFIX;
        String publicKeyFilename = identityBaseFilename + PUBLIC_KEY_FILENAME_SUFFIX;
        Crypto crypto = Util.getCryptoInstance();
        crypto.writeRSAPublicKeyToFile(publicKeyFilename, identity.getPublicKey());
        crypto.writeRSAPrivateKeyToFile(privateKeyFilename, identity.getPrivateKey());
    }

    /**
     * Write the local Telehash identity (RSA key pair) into files named using
     * the default base filename.
     * 
     * @param identity
     *            The identity to write.
     * @throws TelehashException
     *             If a problem happened while writing the identity.
     */
    public void writeIdentity(Identity identity) throws TelehashException {
        writeIdentity(identity, DEFAULT_IDENTITY_FILENAME_BASE);
    }

    private static final String SEEDS_KEY = "seeds";
    private static final String PUBLICKEY_KEY = "pubkey";
    private static final String ENDPOINT_KEY = "endpoint";

    /**
     * Read the local seed cache to obtain a set of nodes that may be used to
     * bootstrap the switch onto the Telehash network.
     * 
     * @param seedsFilename
     *            The filename of the JSON-encoded list of seed nodes.
     * @return A set of seed nodes.
     * @throws TelehashException
     *             If a problem happened while reading and parsing the seeds.
     */
    public Set<Node> readSeeds(String seedsFilename) throws TelehashException {
        Set<Node> nodes = new HashSet<Node>();
        
        JSONTokener tokener;
        try {
            tokener = new JSONTokener(new FileInputStream(seedsFilename));
        } catch (JSONException e) {
            throw new TelehashException(e);
        } catch (FileNotFoundException e) {
            throw new TelehashException(e);
        }
        
        JSONArray array = new JSONArray(tokener);
        for (int i=0; i<array.length(); i++) {
            JSONObject seed = array.getJSONObject(i);
            String publicKeyString = seed.getString(PUBLICKEY_KEY);
            
            String ipString = seed.getString("ip");
            InetAddress address;
            try {
                address = InetAddress.getByName(ipString);  // TODO: ???
            } catch (UnknownHostException e) {
                throw new TelehashException(e);
            }
            int port = seed.getInt("port");
            Endpoint endpoint = new InetEndpoint(address, port);
            
            /*
            byte[] publicKeyBuffer = Util.hexToBytes(publicKeyString);
            if (publicKeyBuffer == null) {
                throw new TelehashException("cannot parse public key hex string");
            }
            RSAPublicKey publicKey = Util.getCryptoInstance().decodeRSAPublicKey(publicKeyBuffer);
             */
            RSAPublicKey publicKey = Util.getCryptoInstance().parseRSAPublicKeyFromPEM(publicKeyString);
            Node node = new Node(publicKey, endpoint);
            nodes.add(node);
        }
        
        return nodes;
    }

}
