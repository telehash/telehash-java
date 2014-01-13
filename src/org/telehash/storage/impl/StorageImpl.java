package org.telehash.storage.impl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.telehash.core.Identity;
import org.telehash.core.Node;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.RSAPrivateKey;
import org.telehash.crypto.RSAPublicKey;
import org.telehash.network.InetPath;
import org.telehash.network.Path;
import org.telehash.storage.Storage;

/**
 * This class contains implementations for the storage functions needed by
 * Telehash.
 */
public class StorageImpl implements Storage {
    
    private static final String DEFAULT_IDENTITY_FILENAME_BASE = "telehash-identity";
    private static final String PRIVATE_KEY_FILENAME_SUFFIX = ".key";
    private static final String PUBLIC_KEY_FILENAME_SUFFIX = ".pub";
    private static final String IPV4_ADDRESS_KEY = "ip";
    private static final String IPV4_PORT_KEY = "port";
    private static final String IPV6_ADDRESS_KEY = "ip6";
    private static final String IPV6_PORT_KEY = "port6";

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
                Telehash.get().getCrypto().readRSAPrivateKeyFromFile(privateKeyFilename);
        RSAPublicKey publicKey =
                Telehash.get().getCrypto().readRSAPublicKeyFromFile(publicKeyFilename);
        return new Identity(Telehash.get().getCrypto().createRSAKeyPair(publicKey, privateKey));        
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
        Crypto crypto = Telehash.get().getCrypto();
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

    private static final String PUBLICKEY_KEY = "pubkey";

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
            
            // parse seed paths
            List<Path> paths = new ArrayList<Path>();
            if (seed.has(IPV4_ADDRESS_KEY)) {
                String ipString = seed.getString(IPV4_ADDRESS_KEY);
                InetAddress address;
                try {
                    address = InetAddress.getByName(ipString);  // TODO: ???
                } catch (UnknownHostException e) {
                    throw new TelehashException(e);
                }
                int port = seed.getInt(IPV4_PORT_KEY);
                InetPath ipv4Path = new InetPath(address, port);
                if (! (ipv4Path.getAddress() instanceof Inet4Address)) {
                    ipv4Path = null;
                }
                paths.add(ipv4Path);
            }
            if (seed.has(IPV6_ADDRESS_KEY)) {
                String ipString = seed.getString(IPV6_ADDRESS_KEY);
                InetAddress address;
                try {
                    address = InetAddress.getByName(ipString);  // TODO: ???
                } catch (UnknownHostException e) {
                    throw new TelehashException(e);
                }
                int port = seed.getInt(IPV6_PORT_KEY);
                InetPath ipv6Path = new InetPath(address, port);
                if (! (ipv6Path.getAddress() instanceof Inet6Address)) {
                    ipv6Path = null;
                }
                paths.add(ipv6Path);
            }
            if (paths.isEmpty()) {
                throw new TelehashException("no valid network paths found for seed!");
            }
            
            RSAPublicKey publicKey =
                    Telehash.get().getCrypto().parseRSAPublicKeyFromPEM(publicKeyString);
            Node node = new Node(publicKey, paths.get(0));
            nodes.add(node);
        }
        
        return nodes;
    }

}
