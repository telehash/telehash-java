package org.telehash.test.mesh;

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
import org.telehash.core.Log;
import org.telehash.core.TelehashException;

public class ThreeLevelMeshTest {
    
    private static final int NODE_SEED = 0;
    private static final int NUM_NODES = 5;
    private static final int NODE_A = 3;
    private static final int NODE_B = 4;
    
    private List<TelehashTestInstance> mNodes;

    @Before
    public void setUp() throws Exception {
        mNodes = TelehashTestInstance.createThreeLevelTopology();
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
        
        src.getSwitch().openLine(dst.getNode(), new CompletionHandler<Line>() {
            @Override
            public void failed(Throwable exc, Object attachment) {
                Log.i("line open failed");
            }
            @Override
            public void completed(Line result, Object attachment) {
                Log.i("line open success");
            }
        }, null);
        
        // TODO: signal failure/success/timeout via Object.notify().
        Thread.sleep(1000);
        
        // assure src has a line open to dst.
        assertLineOpen(src, dst);
        assertLineOpen(dst, src);
    }

    @Test
    public void testPeerConnect() throws Exception {
        final TelehashTestInstance seed = mNodes.get(NODE_SEED);
        final TelehashTestInstance src = mNodes.get(NODE_A);
        final TelehashTestInstance dst = mNodes.get(NODE_B);
        Log.i("OPEN "+src.getNode()+" -> "+dst.getNode());

        // src opens a line to the seed
        src.getSwitch().openLine(seed.getNode(), new CompletionHandler<Line>() {
            @Override
            public void failed(Throwable exc, Object attachment) {
                Log.i("line open failed");
            }
            @Override
            public void completed(Line line, Object attachment) {
                Log.i("line open success");
                
                // src seeks the dst
                Channel channel = line.openChannel("peer", new ChannelHandler() {
                    @Override
                    public void handleError(Channel channel, Throwable error) {
                        Log.i("peer failed");
                    }
                    @Override
                    public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
                    }
                });

                Log.i("peer channel open success");
                
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
