package org.telehash.test.network;

import org.telehash.network.Network;

public class NetworkSimulator {

    private Router mRouter = new Router();

    public Network createNode(String addressString, int port) {
        return new FakeNetworkImpl(mRouter, addressString);
    }

    public void waitForQuiescence(long time) {
        mRouter.waitForQuiescence(time);
    }
}
