package org.telehash.dht;

import org.telehash.core.HashName;
import org.telehash.core.Log;
import org.telehash.core.Node;
import org.telehash.core.PeerNode;
import org.telehash.core.Telehash;

import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

public class NodeTracker {
    private static final int BUCKET_COUNT = 256;
    private static final int MAX_BUCKET_SIZE = 9;
    private static final long NANOSECONDS_PER_SECOND = 1000000L;
    private static final long NANOSECONDS_PER_HOUR = 3600 * NANOSECONDS_PER_SECOND;
    private static final long BUCKET_REFRESH_TIME_NS = 1 * NANOSECONDS_PER_HOUR;

    // TODO: synchronize access to NodeTracker

    private static class TrackedNode {
        public PeerNode node;

        // TODO: lastValidTime, state = { GOOD, UNKNOWN, BAD }

        public TrackedNode(PeerNode node) {
            this.node = node;
        }

        // Java identity

        @Override
        public boolean equals(Object other) {
            if (other instanceof TrackedNode && ((TrackedNode) other).node.equals(node)) {
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
        Set<TrackedNode> mTrackedNodes = new HashSet<TrackedNode>();
        long mLastNodeLookupTime = -1;

        // TODO: get count of nodes in each state

        // TODO:
        // "Each k-bucket is kept sorted by time last seen -- least-recently
        // seen
        // node at the head, most-recently seen at the tail."

        public int size() {
            return mTrackedNodes.size();
        }

        public void submitNode(PeerNode node) {
            TrackedNode trackedNode = new TrackedNode(node);
            if (mTrackedNodes.contains(trackedNode)) {
                // already present in bucket
                return;
            }
            if (mTrackedNodes.size() == MAX_BUCKET_SIZE) {
                // TODO: take action to possibly prune the bucket

                return;
            }
            mTrackedNodes.add(trackedNode);
            mLastNodeLookupTime = System.nanoTime();
        }

        public void accumulateNodes(Set<PeerNode> nodes) {
            for (TrackedNode trackedNode : mTrackedNodes) {
                nodes.add(trackedNode.node);
            }
        }
    }

    private Bucket[] mBuckets = new Bucket[BUCKET_COUNT];

    private PeerNode mLocalNode;

    public NodeTracker(PeerNode localNode) {
        mLocalNode = localNode;

        for (int i=0; i<BUCKET_COUNT; i++) {
            mBuckets[i] = new Bucket();
        }
    }

    public int size() {
        int size = 0;
        for (int i=0; i<BUCKET_COUNT; i++) {
            size += mBuckets[i].size();
        }
        return size;
    }

    public void submitNode(PeerNode node) {
        int distance = mLocalNode.getHashName().distanceMagnitude(node.getHashName());
        if (distance == -1) {
            // the referenced node is us.
            return;
        }
        Bucket bucket = mBuckets[distance];
        bucket.submitNode(node);
    }

    /**
     * Fetch a set of nodes closest to the target hashname.
     *
     * @param targetHashName
     *            The target hash name.
     * @param maxNodes
     *            The maximum number of nodes to fetch.
     * @return A set of nodes sorted by increasing distance from the target
     *         hashname.
     */
    public SortedSet<PeerNode> getClosestNodes(HashName targetHashName, int maxNodes) {
        SortedSet<PeerNode> sortedNodes =
                new TreeSet<PeerNode>(new NodeDistanceComparator(targetHashName));

        // determine the starting bucket based on the distance from me.
        int startingBucket = mLocalNode.getHashName().distanceMagnitude(targetHashName);
        if (startingBucket == -1) {
            // the target node is ourself -- scan all buckets
            for (int i=0; i<BUCKET_COUNT && sortedNodes.size() < maxNodes; i++) {
                mBuckets[i].accumulateNodes(sortedNodes);
            }
        } else {
            // the target node is not ourself -- scan the target bucket
            // first, followed by closer buckets, followed by farther buckets.

            // scan the target bucket
            mBuckets[startingBucket].accumulateNodes(sortedNodes);

            // scan closer buckets
            for (int i = (startingBucket - 1); i >= 0 && sortedNodes.size() < maxNodes; i--) {
                mBuckets[i].accumulateNodes(sortedNodes);
            }

            // scan farther buckets
            for (int i = (startingBucket + 1);
                    i < BUCKET_COUNT && sortedNodes.size() < maxNodes;
                    i++) {
                mBuckets[i].accumulateNodes(sortedNodes);
            }
        }

        // trim nodes
        while (sortedNodes.size() > maxNodes) {
            sortedNodes.remove(sortedNodes.last());
        }

        return sortedNodes;
    }

    /**
     * Refresh all buckets by performing a node lookup for a random
     * hashname within buckets that haven't had a node lookup in the
     * past hour.
     */
    public void refreshBuckets() {
        Log.i("perform self-seek");
        NodeLookupTask lookup = new NodeLookupTask(
                Telehash.get(),
                this,
                mLocalNode.getHashName(),
                new NodeLookupTask.Handler() {
                    @Override
                    public void handleError(NodeLookupTask task, Throwable e) {
                        Log.e("error performing self-seek", e);
                    }

                    @Override
                    public void handleCompletion(NodeLookupTask task, Node self) {
                        Log.i("self-seek finished: "+self);
                        if (self == null) {
                            Log.e("could not seek self!  aborting refresh");
                            return;
                        }
                        int neighborDistance = 0;
                        Node neighbor = task.getClosestVisitedNode();
                        if (neighbor != null) {
                            neighborDistance = mLocalNode.getHashName().distanceMagnitude(
                                    neighbor.getHashName()
                            );
                            Log.i("nearest neighbor = "+neighbor+" distance="+neighborDistance);
                        } else {
                            Log.i("no nearest neighbor");
                        }

                        long now = System.nanoTime();
                        for (int i=neighborDistance; i<BUCKET_COUNT; i++) {
                            Log.i("considering bucket["+i+"] of size="+mBuckets[i].size()
                                    +": "+mBuckets[i]);
                            if (mBuckets[i].mLastNodeLookupTime == -1 ||
                                    ((now - mBuckets[i].mLastNodeLookupTime) >
                                    BUCKET_REFRESH_TIME_NS)) {
                                refreshBucket(i);
                            }
                        }
                    }
                }
        );
        lookup.start();
    }

    /**
     * Refresh the specified bucket by performing a node lookup for a
     * random hashname within the bucket.
     *
     * @param bucket The index of the bucket to refresh.
     */
    private void refreshBucket(final int bucket) {
        Log.i("bucket[%d] start refresh", bucket);
        HashName hashName = DHT.getRandomHashName(mLocalNode.getHashName(), bucket);
        NodeLookupTask lookup = new NodeLookupTask(
                Telehash.get(),
                this,
                hashName,
                new NodeLookupTask.Handler() {
                    @Override
                    public void handleError(NodeLookupTask task, Throwable e) {
                        Log.e("error refreshing bucket %d: ", bucket, e);
                    }

                    @Override
                    public void handleCompletion(NodeLookupTask task, Node result) {
                        Log.i("bucket[%d] refreshed.", bucket);
                    }
                }
        );
        lookup.start();
    }

    public void dump() {
        Log.d("tracking "+size()+" nodes:");
        for (int i=0; i<BUCKET_COUNT; i++) {
            if (mBuckets[i].size() > 0) {
                StringBuilder sb = new StringBuilder();
                sb.append("["+i+"] ");
                for (TrackedNode trackedNode : mBuckets[i].mTrackedNodes) {
                    sb.append(trackedNode.node+" ");
                }
                Log.d(sb.toString());
            }
        }
    }
}
