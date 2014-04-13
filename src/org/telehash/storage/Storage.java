package org.telehash.storage;

import org.telehash.core.Identity;
import org.telehash.core.Node;
import org.telehash.core.TelehashException;

import java.util.Set;

/**
 * This interface contains methods that may be used to read and write Telehash
 * identities and seed cache information. Concrete implementations suitable for
 * specific platforms may be developed, and applications are free to extend
 * these implementations or provide their own.
 */
public interface Storage {
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
    public Identity readIdentity(String identityBaseFilename) throws TelehashException;

    /**
     * Read the local Telehash identity (RSA key pair) from files named using
     * the default base filename.
     *
     * @return The read and parsed Telehash identity.
     * @throws TelehashException
     *             If a problem happened while reading and parsing the identity.
     */
    public Identity readIdentity() throws TelehashException;

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
            throws TelehashException;

    /**
     * Write the local Telehash identity (RSA key pair) into files named using
     * the default base filename.
     *
     * @param identity
     *            The identity to write.
     * @throws TelehashException
     *             If a problem happened while writing the identity.
     */
    public void writeIdentity(Identity identity) throws TelehashException;

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
    public Set<Node> readSeeds(String seedsFilename) throws TelehashException;
}
