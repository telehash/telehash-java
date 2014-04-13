package org.telehash.test.network;

import org.telehash.core.TelehashException;
import org.telehash.network.Datagram;
import org.telehash.network.DatagramHandler;
import org.telehash.network.InetPath;
import org.telehash.network.Network;
import org.telehash.network.Path;
import org.telehash.network.Reactor;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

/**
 * This class contains fake implementations for the network operations needed by
 * Telehash.
 */
public class FakeNetworkImpl implements Network, DatagramHandler {

    private Router mRouter;
    private Map<Integer,FakeReactorImpl> mReactorMap = new HashMap<Integer,FakeReactorImpl>();
    private InetPath mPath;

    public FakeNetworkImpl(Router router, String addressString) {
        mRouter = router;
        try {
            mPath = (InetPath)parsePath(addressString, 0);
        } catch (TelehashException e) {
            throw new RuntimeException(e);
        }
        router.registerNetwork(this);
    }

    /** intentionally package-private */
    InetPath getPath() {
        return mPath;
    }

    /** intentionally package-private */
    Router getRouter() {
        return mRouter;
    }

    /**
     * Parse a string representing a network address.
     *
     * TODO: we shouldn't need this... why is "see" hard-coded for IP addressing in the protocol?
     *
     * @param addressString
     *            The path string to parse.
     * @return The network path object.
     * @throws TelehashException
     *             If a problem occurred while parsing the path.
     */
    @Override
    public Path parsePath(String addressString, int port) throws TelehashException {
        InetAddress address;
        try {
            address = InetAddress.getByName(addressString);
        } catch (UnknownHostException e) {
            throw new TelehashException("invalid address or unknown host in path");
        }
        return new InetPath(address, port);
    }

    /**
     * Get preferred local path
     * TODO: This will certainly change... we need to support multiple network interfaces!
     */
    @Override
    public Path getPreferredLocalPath() throws TelehashException {
        return mPath;
    }

    /**
     * Provision a new reactor i/o engine listening on the specified port.
     *
     * @param port The IP port on which to listen.
     * @return The reactor.
     */
    @Override
    public Reactor createReactor(int port) {
        FakeReactorImpl reactor = new FakeReactorImpl(this, port);
        mReactorMap.put(port, reactor);
        return reactor;
    }

    @Override
    public void handleDatagram(Datagram datagram) {
        InetPath path = (InetPath)datagram.getDestination();
        if (mReactorMap.containsKey(path.getPort())) {
            mReactorMap.get(path.getPort()).handleDatagram(datagram);
        }
    }

}
