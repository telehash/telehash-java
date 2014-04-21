package org.telehash.test.mesh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.CompletionHandler;
import org.telehash.core.Line;
import org.telehash.core.Log;

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

        src.getSwitch().getLineManager().openLine(
                dst.getNode(),
                false,
                new CompletionHandler<Line>() {
                    @Override
                    public void failed(Throwable exc, Object attachment) {
                        Log.i("line open failed");
                    }
                    @Override
                    public void completed(Line result, Object attachment) {
                        Log.i("line open success");
                    }
                },
                null
        );

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
