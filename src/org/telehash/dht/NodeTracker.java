package org.telehash.dht;

import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.telehash.core.Node;

public class NodeTracker {
    private static final int BUCKET_COUNT = 256;
    private static final int MAX_BUCKET_SIZE = 9;

    private static class NodeDistanceComparator implements Comparator<Node> {
        private byte[] mTargetHashName;
        public NodeDistanceComparator(byte[] targetHashName) {
            mTargetHashName = targetHashName;
        }
        @Override
        public int compare(Node a, Node b) {
            int da = DHT.distance(a.getHashName(), mTargetHashName);
            int db = DHT.distance(b.getHashName(), mTargetHashName);
            if (da < db) {
                return -1;
            } else if (da > db) {
                return +1;
            } else {
                return 0;
            }
        }
    }

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

    /**
     * Fetch a set of nodes closest to the target hashname.
     * 
     * @param targetHashName The target hash name.
     * @param maxNodes The maximum number of nodes to fetch.
     * @return A set of nodes sorted by increasing distance from the target hashname.
     */
    public Set<Node> getClosestNodes(byte[] targetHashName, int maxNodes) {
        SortedSet<Node> sortedNodes = new TreeSet<Node>(new NodeDistanceComparator(targetHashName));
        
        // determine the starting bucket based on the distance from me.
        int startingBucket = DHT.distance(mLocalNode.getHashName(), targetHashName);
        
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
