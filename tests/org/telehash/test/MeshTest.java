package org.telehash.test;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.CompletionHandler;
import org.telehash.core.HashName;
import org.telehash.core.Line;
import org.telehash.core.TelehashException;

public class MeshTest {
    
    private static final int START_PORT = 6000;
    private static final int NUM_NODES = 3;
    private static final int NODE_SEED = 0;
    private static final int NODE_A = 1;
    private static final int NODE_B = 2;
    
    private List<TelehashTestInstance> mNodes;

    @Before
    public void setUp() throws Exception {
        mNodes = TelehashTestInstance.createStarTopology(NUM_NODES, START_PORT);
    }

    @After
    public void tearDown() throws Exception {
        for (TelehashTestInstance node : mNodes) {
            node.stop();
        }
    }

    @Test
    public void testOpenLine() throws Exception {
        TelehashTestInstance src = mNodes.get(NODE_A);
        TelehashTestInstance dst = mNodes.get(NODE_B);
        
        src.getSwitch().openLine(dst.getNode(), new CompletionHandler<Line>() {
            @Override
            public void failed(Throwable exc, Object attachment) {
                System.out.println("line open failed");
            }
            @Override
            public void completed(Line result, Object attachment) {
                System.out.println("line open success");
            }
        }, null);
        
        // TODO: signal failure/success/timeout via Object.notify().
        Thread.sleep(1000);
        
        // assure src has a line open to dst.
        assertLineOpen(src, dst);
        assertLineOpen(dst, src);
    }

    // TODO: this doesn't do anything useful at the moment; it's just to
    // exercise code under development.  Fix.
    @Test
    public void testPeerConnect() throws Exception {
        final TelehashTestInstance seed = mNodes.get(NODE_SEED);
        final TelehashTestInstance src = mNodes.get(NODE_A);
        final TelehashTestInstance dst = mNodes.get(NODE_B);
        System.out.println("OPEN "+src.getNode()+" -> "+dst.getNode());

        // src opens a line to the seed
        src.getSwitch().openLine(seed.getNode(), new CompletionHandler<Line>() {
            @Override
            public void failed(Throwable exc, Object attachment) {
                System.out.println("line open failed");
            }
            @Override
            public void completed(Line line, Object attachment) {
                System.out.println("line open success");
                
                // src seeks the dst
                Channel channel = line.openChannel("peer", new ChannelHandler() {
                    @Override
                    public void handleError(Channel channel, Throwable error) {
                        System.out.println("peer failed");
                    }
                    @Override
                    public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
                    }
                });

                System.out.println("peer channel open success");
                
                Map<String,Object> fields = new HashMap<String,Object>();
                fields.put("peer", dst.getNode().getHashName().asHex());
                try {
                    channel.send(null, fields, false);
                } catch (TelehashException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

            }
        }, null);
        
        // TODO: signal failure/success/timeout via Object.notify().
        Thread.sleep(1000);

        // assure src has a line open to dst.
        assertLineOpen(src, dst);
        assertLineOpen(dst, src);
    }
    
    protected void assertLineOpen(TelehashTestInstance a, TelehashTestInstance b) {
        // assure A has a line open to B.
        boolean found = false;
        Set<Line> aLines = a.getSwitch().getLines();
        for (Line line : aLines) {
            if (line.getRemoteNode().equals(b.getNode())) {
                found = true;
            }
        }
        assertTrue(found);        
    }
}
