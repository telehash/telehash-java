package org.telehash.test.mesh;

import org.telehash.test.network.NetworkSimulator;

import java.util.List;

public class Mesh {
    private List<TelehashTestInstance> mInstances;
    private NetworkSimulator mNetworkSimulator;

    public Mesh(List<TelehashTestInstance> instances, NetworkSimulator networkSimulator) {
        mInstances = instances;
        mNetworkSimulator = networkSimulator;
    }

    public List<TelehashTestInstance> getInstances() {
        return mInstances;
    }

    public NetworkSimulator getNetworkSimulator() {
        return mNetworkSimulator;
    }

    public void waitForQuiescence(long time) {
        mNetworkSimulator.waitForQuiescence(time);
    }
}
