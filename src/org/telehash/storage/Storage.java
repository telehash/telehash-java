package org.telehash.storage;

import org.telehash.core.LocalNode;
import org.telehash.core.SeedNode;
import org.telehash.core.TelehashException;

import java.util.Set;

/**
 * This interface contains methods that may be used to read and write Telehash
 * local node keys and seed cache information. Concrete implementations suitable
 * for specific platforms may be developed, and applications are free to extend
 * these implementations or provide their own.
 */
public interface Storage {
    /**
     * Read the local Telehash node keys from files named using the specified
     * base filename.
     *
     * @param localNodeBaseFilename
     *            The base filename, e.g. "localnode".
     * @return The read and parsed Telehash local node.
     * @throws TelehashException
     *             If a problem happened while reading and parsing the local node.
     */
    public LocalNode readLocalNode(String localNodeBaseFilename) throws TelehashException;

    /**
     * Read the local Telehash node keys from files named using the default
     * base filename.
     *
     * @return The read and parsed Telehash local node.
     * @throws TelehashException
     *             If a problem happened while reading and parsing the local node.
     */
    public LocalNode readLocalNode() throws TelehashException;

    /**
     * Write the local Telehash node keys into files named using the specified
     * base filename.
     *
     * @param localNode
     *            The local node to write.
     * @param localNodeBaseFilename
     *            The base filename, e.g. "localnode".
     * @throws TelehashException
     *             If a problem happened while writing the local node.
     */
    public void writeLocalNode(LocalNode localNode, String localNodeBaseFilename)
            throws TelehashException;

    /**
     * Write the local Telehash local node (RSA key pair) into files named using
     * the default base filename.
     *
     * @param localNode
     *            The local node to write.
     * @throws TelehashException
     *             If a problem happened while writing the local node.
     */
    public void writeLocalNode(LocalNode localNode) throws TelehashException;

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
    public Set<SeedNode> readSeeds(String seedsFilename) throws TelehashException;
}
