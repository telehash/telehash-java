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
import org.telehash.core.Line;
import org.telehash.core.Log;
import org.telehash.core.TelehashException;

public class StarMeshTest {
    private static final int NUM_NODES = 3;
    private static final int NODE_SEED = 0;
    private static final int NODE_A = 1;
    private static final int NODE_B = 2;
    
    private List<TelehashTestInstance> mNodes;

    @Before
    public void setUp() throws Exception {
        mNodes = TelehashTestInstance.createStarTopology(NUM_NODES);
    }

    @After
    public void tearDown() throws Exception {
        for (TelehashTestInstance node : mNodes) {
            node.stop();
        }
    }

    @Test
    public void testOpenLine() throws Exception {
        Log.i("testOpenLine()");
        TelehashTestInstance src = mNodes.get(NODE_A);
        TelehashTestInstance dst = mNodes.get(NODE_B);
        
        src.getSwitch().getLineManager().openLine(dst.getNode(), false, new CompletionHandler<Line>() {
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
        
        src.getSwitch().openChannel(seed.getNode(), "peer", new ChannelHandler() {
			@Override
			public void handleError(Channel channel, Throwable error) {
				Log.i("cannot open peer channel");
			}
			@Override
			public void handleIncoming(Channel channel,
					ChannelPacket channelPacket) {
				Log.i("expected silence, but received on channel: "+channelPacket);
			}
			@Override
			public void handleOpen(Channel channel) {
                Map<String,Object> fields = new HashMap<String,Object>();
                fields.put("peer", dst.getNode().getHashName().asHex());
                try {
                    channel.send(null, fields, false);
                } catch (TelehashException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
			}
		});
        
        // TODO: signal failure/success/timeout via Object.notify().
        Thread.sleep(1000);

        // assure src has a line open to dst.
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
