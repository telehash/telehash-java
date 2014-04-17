package org.telehash.storage.impl;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.FingerprintSet;
import org.telehash.core.HashName;
import org.telehash.core.Identity;
import org.telehash.core.Log;
import org.telehash.core.Node;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.CipherSet;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.HashNameKeyPair;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.network.Path;
import org.telehash.storage.Storage;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * This class contains implementations for the storage functions needed by
 * Telehash.
 */
public class StorageImpl implements Storage {

    private static final String DEFAULT_IDENTITY_FILENAME_BASE = "telehash-identity";
    private static final String PRIVATE_KEY_FILENAME_SUFFIX = ".key";
    private static final String PUBLIC_KEY_FILENAME_SUFFIX = ".pub";
    private static final String PATHS_KEY = "paths";

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
    @Override
    public Identity readIdentity(String identityBaseFilename) throws TelehashException {
        String privateKeyFilename = identityBaseFilename + PRIVATE_KEY_FILENAME_SUFFIX;
        String publicKeyFilename = identityBaseFilename + PUBLIC_KEY_FILENAME_SUFFIX;

        // read keys
        HashNamePrivateKey privateKey =
                Telehash.get().getCrypto().readRSAPrivateKeyFromFile(privateKeyFilename);
        HashNamePublicKey publicKey =
                Telehash.get().getCrypto().readRSAPublicKeyFromFile(publicKeyFilename);

        Map<CipherSetIdentifier,HashNameKeyPair> keyPairs =
                new TreeMap<CipherSetIdentifier,HashNameKeyPair>();
        keyPairs.put(
                Telehash.get().getCrypto().getCipherSet().getCipherSetId(),
                Telehash.get().getCrypto().createHashNameKeyPair(publicKey, privateKey)
        );
        return new Identity(keyPairs);
    }

    /**
     * Read the local Telehash identity (RSA key pair) from files named using
     * the default base filename.
     *
     * @return The read and parsed Telehash identity.
     * @throws TelehashException
     *             If a problem happened while reading and parsing the identity.
     */
    @Override
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
    @Override
    public void writeIdentity(Identity identity, String identityBaseFilename)
            throws TelehashException {
        String privateKeyFilename = identityBaseFilename + PRIVATE_KEY_FILENAME_SUFFIX;
        String publicKeyFilename = identityBaseFilename + PUBLIC_KEY_FILENAME_SUFFIX;
        Crypto crypto = Telehash.get().getCrypto();
        CipherSetIdentifier csid = crypto.getCipherSet().getCipherSetId();
        crypto.writeRSAPublicKeyToFile(publicKeyFilename, identity.getHashNamePublicKey(csid));
        crypto.writeRSAPrivateKeyToFile(privateKeyFilename, identity.getHashNamePrivateKey(csid));
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
    @Override
    public void writeIdentity(Identity identity) throws TelehashException {
        writeIdentity(identity, DEFAULT_IDENTITY_FILENAME_BASE);
    }

    private static final String PUBLICKEYS_KEY = "keys";
    private static final String FINGERPRINTS_KEY = "parts";

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
    @Override
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

        JSONObject toplevel = new JSONObject(tokener);
        Iterator<?> toplevelIterator = toplevel.keys();
        while (toplevelIterator.hasNext()) {
            Object keyObject = toplevelIterator.next();
            if (keyObject == null || (! (keyObject instanceof String))) {
                Log.w("unknown json key object type: "+keyObject);
                continue;
            }
            String keyString = (String)keyObject;

            HashName hashName = new HashName(Util.hexToBytes(keyString));
            JSONObject seed = toplevel.getJSONObject(keyString);

            FingerprintSet fingerprints = new FingerprintSet(seed.getJSONObject(FINGERPRINTS_KEY));
            if (fingerprints == null) {
                throw new TelehashException("cannot parse fingerprints from seeds json");
            }
            if (! fingerprints.getHashName().equals(hashName)) {
                throw new TelehashException("seed fingerprints do not match hashname");
            }

            // parse seed paths
            List<Path> paths = new ArrayList<Path>();
            if (seed.has(PATHS_KEY)) {
                JSONArray pathsArray = seed.getJSONArray(PATHS_KEY);
                paths.addAll(Path.parsePathArray(pathsArray));
            }
            if (paths.isEmpty()) {
                throw new TelehashException("no valid network paths found for seed!");
            }

            // TODO: support multiple paths per node.
            Node node = new Node(hashName, fingerprints, paths.get(0));

            JSONObject keysObject = seed.getJSONObject(PUBLICKEYS_KEY);
            Iterator<?> keysIter = keysObject.keys();
            while (keysIter.hasNext()) {
                // cipher set id
                Object csidObject = keysIter.next();
                if (! (csidObject instanceof String)) {
                    throw new TelehashException("invalid csid in seeds json");
                }
                String csidString = (String)csidObject;
                CipherSetIdentifier csid = new CipherSetIdentifier((String)csidObject);

                // key
                Object pubkeyObject = keysObject.get(csidString);
                if (! (pubkeyObject instanceof String)) {
                    throw new TelehashException("invalid key in seeds json for csid "+csid);
                }
                String pubkeyString = (String)pubkeyObject;
                byte[] pubkeyBuffer = Util.base64Decode(pubkeyString);
                CipherSet cipherSet = Telehash.get().getCrypto()
                        .getCipherSet(csid);
                if (cipherSet == null) {
                    Log.w("unknown cipher set in seeds json: "+csid);
                    continue;
                }
                HashNamePublicKey publicKey = cipherSet.decodeHashNamePublicKey(pubkeyBuffer);

                // confirm fingerprint
                byte[] publicKeyFingerprint = publicKey.getFingerprint();
                byte[] providedFingerprint = fingerprints.get(csid);
                if (publicKeyFingerprint == null ||
                        providedFingerprint == null ||
                        (! Arrays.equals(publicKeyFingerprint,  providedFingerprint))) {
                    throw new TelehashException("seed pubkey does not match fingerprint");
                }
            }
            nodes.add(node);
        }
        return nodes;
    }
}
