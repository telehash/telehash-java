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
     * Parse a string representing a network endpoint. The string must contain
     * the address family tag, followed by a colon, followed by the
     * family-specific address representation.
     * 
     * @param endpointString
     *            The endpoint string to parse.
     * @return The network endpoint object.
     * @throws TelehashException
     *             If a problem occurred while parsing the endpoint.
     */
    public Endpoint parseEndpoint(String endpointString) throws TelehashException;
}