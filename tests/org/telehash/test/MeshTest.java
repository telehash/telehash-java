package org.telehash.test;

import static org.junit.Assert.*;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.CompletionHandler;
import org.telehash.core.Line;
import org.telehash.core.Node;

public class MeshTest {
    
    private static final int START_PORT = 6000;
    private static final int NUM_NODES = 9;
    
    private List<TelehashTestInstance> mNodes;

    @Before
    public void setUp() throws Exception {
        mNodes = TelehashTestInstance.createNodes(NUM_NODES, START_PORT);
    }

    @After
    public void tearDown() throws Exception {
        for (TelehashTestInstance node : mNodes) {
            node.stop();
        }
    }

    @Test
    public void testOpenLine() throws Exception {
        TelehashTestInstance src = mNodes.get(4);
        TelehashTestInstance dst = mNodes.get(7);
        
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
        
        Thread.sleep(1000);
    }

}
