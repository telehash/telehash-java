package org.telehash.network.impl;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;

import org.telehash.core.TelehashException;
import org.telehash.network.Endpoint;
import org.telehash.network.Network;

/**
 * This class contains implementations for the network operations needed by
 * Telehash.
 */
public class NetworkImpl implements Network {

    private static final String ENDPOINT_INET_PREFIX = "inet:";

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
    @Override
    public Endpoint parseEndpoint(String endpointString) throws TelehashException {
        if (endpointString.startsWith(ENDPOINT_INET_PREFIX)) {
            String inetEndpointString = endpointString.substring(ENDPOINT_INET_PREFIX.length());
            int slashIndex = inetEndpointString.indexOf("/");
            if (slashIndex == -1) {
                throw new TelehashException("cannot parse inet endpoint string");
            }
            String addressString = inetEndpointString.substring(0, slashIndex);
            String portString = inetEndpointString.substring(slashIndex + 1);
            InetAddress address;
            try {
                address = InetAddress.getByName(addressString);
            } catch (UnknownHostException e) {
                throw new TelehashException("invalid address or unknown host in endpoint");
            }
            int port;
            try {
                port = Integer.parseInt(portString);
            } catch (NumberFormatException e) {
                throw new TelehashException("invalid port number in endpoint");
            }
            return new InetEndpoint(address, port);
        } else {
            throw new TelehashException("cannot parse endpoint string");
        }
    }
    
    /**
     * Convert a Java SocketAddress to an Endpoint object.
     * @param socketAddress
     * @return The network endpoint object.
     * @throws TelehashException
     */
    @Override
    public Endpoint socketAddressToEndpoint(SocketAddress socketAddress) throws TelehashException {
        if (! (socketAddress instanceof InetSocketAddress)) {
            throw new TelehashException("unknown socket address type");
        }
        InetSocketAddress inetSocketAddress = (InetSocketAddress)socketAddress;
        return new InetEndpoint(inetSocketAddress.getAddress(), inetSocketAddress.getPort());
    }

}
