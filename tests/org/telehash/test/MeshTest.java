package org.telehash.test;

import static org.junit.Assert.*;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Node;

public class MeshTest {
    
    private static final int START_PORT = 6000;
    private static final int NUM_NODES = 9;
    
    private List<TelehashTestNode> mNodes;

    @Before
    public void setUp() throws Exception {
        mNodes = TelehashTestNode.createNodes(NUM_NODES, START_PORT);
    }

    @After
    public void tearDown() throws Exception {
        for (TelehashTestNode node : mNodes) {
            node.stop();
        }
    }

    @Test
    public void testOpenPacket() throws Exception {
    }

}
