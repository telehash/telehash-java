package org.telehash.storage.impl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
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
import org.telehash.network.Endpoint;
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
        PrivateKey privateKey;
        PublicKey publicKey;
        try {
            Key key;
            key = Util.getCryptoInstance().readKeyFromFile(privateKeyFilename);
            if (key instanceof PrivateKey) {
                privateKey = (PrivateKey)key;
            } else {
                throw new TelehashException("invalid private key");
            }
            key = Util.getCryptoInstance().readKeyFromFile(publicKeyFilename);
            if (key instanceof PublicKey) {
                publicKey = (PublicKey)key;
            } else {
                throw new TelehashException("invalid public key");
            }
        } catch (IOException e) {
            throw new TelehashException("error reading key(s)", e);
        }
        return new Identity(new KeyPair(publicKey, privateKey));        
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
        try {
            Util.getCryptoInstance().writeKeyToFile(privateKeyFilename, identity.getPrivateKey());
        } catch (IOException e) {
            throw new TelehashException(e);
        }
        try {
            Util.getCryptoInstance().writeKeyToFile(publicKeyFilename, identity.getPublicKey());
        } catch (IOException e) {
            throw new TelehashException(e);
        }
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
    private static final String PUBLICKEY_KEY = "publickey";
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
        JSONObject root = new JSONObject(tokener);
        JSONArray array = root.getJSONArray(SEEDS_KEY);
        for (int i=0; i<array.length(); i++) {
            JSONObject seed = array.getJSONObject(i);
            String publicKeyString = seed.getString(PUBLICKEY_KEY);
            String endpointString = seed.getString(ENDPOINT_KEY);
            
            byte[] publicKeyBuffer = Util.hexToBytes(publicKeyString);
            if (publicKeyBuffer == null) {
                throw new TelehashException("cannot parse public key hex string");
            }
            PublicKey publicKey = Util.getCryptoInstance().derToRSAPublicKey(publicKeyBuffer);
            Endpoint endpoint = Util.getNetworkInstance().parseEndpoint(endpointString);
            Node node = new Node(publicKey, endpoint);
            nodes.add(node);
        }
        
        return nodes;
    }

}
