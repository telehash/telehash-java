package org.telehash.test.mesh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Channel;
import org.telehash.core.ChannelHandler;
import org.telehash.core.ChannelPacket;
import org.telehash.core.Line;
import org.telehash.core.Log;
import org.telehash.core.Node;
import org.telehash.core.PlaceholderNode;

import java.util.List;
import java.util.Set;

public class LargeScaleMeshTest {

    // depth 4 = 15 nodes
    // depth 5 = 31 nodes
    // depth 6 = 63 nodes
    private static final int TREE_DEPTH = 5;
    private static final int NUM_NODES = (1<<TREE_DEPTH)-1;
    private static final int NODE_A = NUM_NODES-(1<<(TREE_DEPTH-1));
    private static final int NODE_B = NUM_NODES-1;

    private List<TelehashTestInstance> mNodes;

    @Before
    public void setUp() throws Exception {
        mNodes = TelehashTestInstance.createLargeScaleTopology(TREE_DEPTH);
        assertEquals(mNodes.size(), NUM_NODES);
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
        Node destinationNode = new PlaceholderNode(dst.getNode().getHashName());

        Log.i("TEST: request channel open from "+src.getNode()+" to "+destinationNode);
        src.getSwitch().openChannel(destinationNode, "test", new ChannelHandler() {
            @Override
            public void handleError(Channel channel, Throwable error) {
                Log.e("channel open error:",error);
            }
            @Override
            public void handleIncoming(Channel channel,
                    ChannelPacket channelPacket) {
                Log.i("incoming channel data: "+channelPacket);
            }
            @Override
            public void handleOpen(Channel channel) {
                Log.i("channel open success: "+channel);
            }
        });

        // TODO: signal failure/success/timeout via Object.notify().
        Thread.sleep(1000);

        // assure src has a line open to dst.
        Log.i("TEST: assert line open from "+src.getNode()+" to "+dst.getNode());
        assertLineOpen(src, dst);
        assertLineOpen(dst, src);
    }

    protected void assertLineOpen(TelehashTestInstance a, TelehashTestInstance b) {
        // assure A has a line open to B.
        boolean found = false;
        Set<Line> aLines = a.getSwitch().getLineManager().getLines();
        for (Line line : aLines) {
            if (line.getRemoteNode().equals(b.getNode())) {
                found = true;
            }
        }
        assertTrue(found);
    }
}
