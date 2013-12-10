package org.telehash.dht;

import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.telehash.core.HashName;
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
            if (trackedNodes.contains(trackedNode) && node.getPublicKey() != null) {
                // already present in bucket -- make sure the
                // RSA public key of the tracked node is populated.
                // (This is quite awkward. Maybe we need to maintain a sister
                // collection map to directly access the relevant node?)
                for (TrackedNode existingNode : trackedNodes) {
                    if (existingNode.equals(trackedNode)) {
                        if (existingNode.node.getPublicKey() == null) {
                            existingNode.node.setPublicKey(node.getPublicKey());
                        }
                        break;
                    }
                }
                return;
            }
            if (trackedNodes.size() == MAX_BUCKET_SIZE) {
                // TODO: take action to possibly prune the bucket
                
                return;
            }
            trackedNodes.add(trackedNode);
        }
        
        public void accumulateNodes(Set<Node> nodes) {
            for (TrackedNode trackedNode : trackedNodes) {
                nodes.add(trackedNode.node);
            }
        }
    }
    
    private Bucket[] mBuckets = new Bucket[BUCKET_COUNT];
    
    private Node mLocalNode;

    public NodeTracker(Node localNode) {
        mLocalNode = localNode;
    }
    
    public void submitNode(Node node) {
        if (node.getPublicKey() == null) {
            throw new IllegalArgumentException("attempt to track node without RSA public key.");
        }
        int distance = DHT.logDistance(mLocalNode.getHashName(), node.getHashName());
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

    /**
     * Fetch a set of nodes closest to the target hashname.
     * 
     * @param targetHashName The target hash name.
     * @param maxNodes The maximum number of nodes to fetch.
     * @return A set of nodes sorted by increasing distance from the target hashname.
     */
    public SortedSet<Node> getClosestNodes(HashName targetHashName, int maxNodes) {
        SortedSet<Node> sortedNodes = new TreeSet<Node>(new NodeDistanceComparator(targetHashName));
        
        // determine the starting bucket based on the distance from me.
        int startingBucket = DHT.logDistance(mLocalNode.getHashName(), targetHashName);
        if (startingBucket == -1) {
            // the target node is ourself.
            return new TreeSet<Node>();
        }
        
        // scan the target bucket
        if (mBuckets[startingBucket] != null) {
            mBuckets[startingBucket].accumulateNodes(sortedNodes);
        }
        
        // scan closer buckets
        for (int i=(startingBucket-1); i>=0 && sortedNodes.size()<maxNodes; i--) {
            if (mBuckets[i] != null) {
                mBuckets[i].accumulateNodes(sortedNodes);
            }
        }

        // scan farther buckets
        for (int i=(startingBucket+1); i<BUCKET_COUNT && sortedNodes.size()<maxNodes; i++) {
            if (mBuckets[i] != null) {
                mBuckets[i].accumulateNodes(sortedNodes);
            }
        }
        
        // trim nodes
        while (sortedNodes.size() > maxNodes) {
            sortedNodes.remove(sortedNodes.last());
        }
        
        return sortedNodes;
    }
}
