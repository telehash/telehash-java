package org.telehash.dht;

import java.util.HashSet;
import java.util.Set;

import org.telehash.core.Node;

public class NodeTracker {
    private static final int BUCKET_COUNT = 256;
    private static final int MAX_BUCKET_SIZE = 9;

    private static class TrackedNode {
        public Node node;
        // TODO: lastValidTime, state = { GOOD, UNKNOWN, BAD }
        
        public TrackedNode(Node node) {
            this.node = node;
        }
        
        // Java identity
        
        @Override
        public boolean equals(Object other) {
            if (other instanceof TrackedNode && ((TrackedNode)other).node.equals(node)) {
                return true;
            } else {
                return false;
            }
        }
        
        @Override
        public int hashCode() {
            return node.hashCode();
        }
    }
    
    private static class Bucket {
        Set<TrackedNode> trackedNodes = new HashSet<TrackedNode>();
        
        // TODO: get count of nodes in each state
        
        // TODO:
        // "Each k-bucket is kept sorted by time last seen -- least-recently seen
        // node at the head, most-recently seen at the tail."
        
        public void submitNode(Node node) {
            TrackedNode trackedNode = new TrackedNode(node);
            if (trackedNodes.contains(trackedNode)) {
                // already present in bucket
                return;
            }
            if (trackedNodes.size() == MAX_BUCKET_SIZE) {
                // TODO: take action to possibly prune the bucket
                
                return;
            }
            trackedNodes.add(trackedNode);
        }
    }
    
    private Bucket[] mBuckets = new Bucket[BUCKET_COUNT];
    
    private Node mLocalNode;

    public NodeTracker(Node localNode) {
        mLocalNode = localNode;
    }
    
    public void submitNode(Node node) {
        int distance = DHT.distance(mLocalNode.getHashName(), node.getHashName());
        if (distance == -1) {
            // the referenced node is us.
            return;
        }
        Bucket bucket = mBuckets[distance];
        if (bucket == null) {
            bucket = new Bucket();
            mBuckets[distance] = bucket;
        }
        bucket.submitNode(node);
    }
}
