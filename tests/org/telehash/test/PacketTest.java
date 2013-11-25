package org.telehash.test;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Identity;
import org.telehash.core.Node;
import org.telehash.core.PacketFactory;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;
import org.telehash.network.Network;

public class PacketTest {
    
    private Crypto mCrypto;
    private Network mNetwork;

    @Before
    public void setUp() throws Exception {
        mCrypto = Util.getCryptoInstance();
        mNetwork = Util.getNetworkInstance();
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testOpenPacket() throws Exception {
        Identity localIdentity = mCrypto.generateIdentity();
        Identity remoteIdentity = mCrypto.generateIdentity();
        Node remoteNode = new Node(
                remoteIdentity.getPublicKey(),
                mNetwork.parseEndpoint("inet:127.0.0.1/4242")
        );
        
        PacketFactory packetFactory = new PacketFactory(localIdentity);        
        packetFactory.createOpenPacket(remoteNode);
        
        // TODO
        assertTrue(true);
    }

}
