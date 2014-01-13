package org.telehash.network;

import java.net.SocketAddress;

import org.telehash.core.TelehashException;

/**
 * This interface contains methods that may be used to perform the network
 * operations needed by Telehash. Concrete implementations suitable for specific
 * platforms and/or specific network technologies may be developed, and
 * applications are free to extend these implementations or provide their own.
 */
public interface Network {
    /**
     * Parse a string representing a network address. 
     * 
     * @param addressString
     *            The path string to parse.
     * @return The network path object.
     * @throws TelehashException
     *             If a problem occurred while parsing the path.
     */
    public Path parsePath(String addressString, int port) throws TelehashException;

    /**
     * Convert a Java SocketAddress to a Path object.
     * @param socketAddress
     * @return The network path object.
     * @throws TelehashException
     */
    public Path socketAddressToPath(SocketAddress socketAddress) throws TelehashException;

    /**
     * Get preferred local path
     * TODO: This will certainly change... we need to support multiple network interfaces!
     */
    public Path getPreferredLocalPath() throws TelehashException;
}
