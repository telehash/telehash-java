package org.telehash.core;

import org.telehash.crypto.Crypto;
import org.telehash.crypto.impl.CryptoImpl;
import org.telehash.network.Network;
import org.telehash.network.impl.NetworkImpl;
import org.telehash.storage.Storage;
import org.telehash.storage.impl.StorageImpl;

public class Telehash {

    private Crypto mCrypto;
    private Storage mStorage;
    private Network mNetwork;
    private LocalNode mLocalNode;
    private Switch mSwitch;

    public Telehash() {
        mCrypto = new CryptoImpl();
        mStorage = new StorageImpl();
        mNetwork = new NetworkImpl();
        mLocalNode = null;
        mSwitch = null;
    }

    public Telehash(LocalNode localNode) {
        mCrypto = new CryptoImpl();
        mStorage = new StorageImpl();
        mNetwork = new NetworkImpl();
        mLocalNode = localNode;
        mSwitch = null;
    }

    public Telehash(LocalNode localNode, Crypto crypto, Storage storage, Network network) {
        mLocalNode = localNode;
        mCrypto = crypto;
        mStorage = storage;
        mNetwork = network;
        mSwitch = null;
    }

    public Crypto getCrypto() {
        return mCrypto;
    }

    public Storage getStorage() {
        return mStorage;
    }

    public Network getNetwork() {
        return mNetwork;
    }

    public void setLocalNode(LocalNode localNode) {
        mLocalNode = localNode;
    }
    public LocalNode getLocalNode() {
        return mLocalNode;
    }

    public void setSwitch(Switch telehashSwitch) {
        mSwitch = telehashSwitch;
    }
    public Switch getSwitch() {
        return mSwitch;
    }

    private static ThreadLocal<Telehash> sThreadLocal = new ThreadLocal<Telehash>();

    public static Telehash get() {
        Telehash telehash = sThreadLocal.get();
        if (telehash == null) {
            telehash = new Telehash();
            sThreadLocal.set(telehash);
        }
        return telehash;
    }

    public void setThreadLocal() {
        sThreadLocal.set(this);
    }
}
