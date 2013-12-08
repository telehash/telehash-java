package org.telehash.dht;

import java.util.Set;

import org.telehash.core.Node;
import org.telehash.core.Switch;

public class DHT {

    private Switch mSwitch;
    private Node mLocalNode;
    
    private NodeTracker mNodeTracker;
        
    public DHT(Switch telehashSwitch, Node localNode, Set<Node> seeds) {
        mSwitch = telehashSwitch;
        mLocalNode = localNode;
        mNodeTracker = new NodeTracker(localNode);
        
        // install seeds in k-buckets.
        if (seeds != null) {
            for (Node node : seeds) {
                mNodeTracker.submitNode(node);
            }
        }
    }

    public void init() {
        // TODO: implement bucket refresh
        
        // TODO: implement bootstrap (refresh all buckets)
    }

    /**
     * Return the hashspace distance between the two hashnames. This is defined
     * as the binary logarithm of the xor of the two hashnames (or -1, if the
     * hashnames are identical). This distance metric is suitable for use as an
     * index into an array of buckets. (Unless the returned value is -1
     * indicating the hashnames are the same, in which case nothing should be
     * stored in a bucket.)
     * 
     * The returned value will always be between -1 and 255, inclusive.
     * 
     * @param A
     *            The first hashname.
     * @param B
     *            The second hashname.
     * @return The distance, or -1 if the hashnames are identical.
     */
    public static int distance(byte[] A, byte[] B) {
        // opportunities for optimization abound.
        // http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious
        
        if (A == null || B == null || A.length != Node.HASHNAME_SIZE || B.length != Node.HASHNAME_SIZE) {
            throw new IllegalArgumentException("invalid hashname");
        }
        for (int i=0; i<Node.HASHNAME_SIZE; i++) {
            int c = A[i] ^ B[i];
            if (c != 0) {
                for (int j=0; j<8; j++) {
                    if ((c & 0x80) != 0) {
                        return (Node.HASHNAME_SIZE-i-1)*8 + (8-j-1);
                    }
                    c = c << 1;
                }
            }
        }
        return -1;
    }
}
