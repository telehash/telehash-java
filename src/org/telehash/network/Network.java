package org.telehash.network;

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
     * Get preferred local path
     * TODO: This will certainly change... we need to support multiple network interfaces!
     */
    public Path getPreferredLocalPath() throws TelehashException;
    
    /**
     * Provision a new reactor i/o engine listening on the specified port.
     * 
     * @param port The IP port on which to listen.
     * @return The reactor. 
     */
    public Reactor createReactor(int port);
}
