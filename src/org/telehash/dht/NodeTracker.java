package org.telehash.dht;

import org.telehash.core.Channel;
import org.telehash.core.ChannelPacket;
import org.telehash.core.CompletionHandler;
import org.telehash.core.CounterTrigger;
import org.telehash.core.HashName;
import org.telehash.core.Line;
import org.telehash.core.LocalNode;
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

    private static class Bucket {
        Set<Link> mLinks = new HashSet<Link>();
        long mLastNodeLookupTime = -1;

        // TODO: get count of nodes in each state

        // TODO:
        // "Each k-bucket is kept sorted by time last seen -- least-recently
        // seen
        // node at the head, most-recently seen at the tail."

        public int size() {
            return mLinks.size();
        }

        public void addLink(Link link) {
            if (mLinks.contains(link)) {
                // already present in bucket
                return;
            }
            if (mLinks.size() == MAX_BUCKET_SIZE) {
                // TODO: take action to possibly prune the bucket

                return;
            }
            mLinks.add(link);
            mLastNodeLookupTime = System.nanoTime();
        }

        public void removeLink(Link link) {
            mLinks.remove(link);
        }

        public void accumulateActiveNodes(Set<PeerNode> nodes) {
            for (Link link : mLinks) {
                if (link.getState() == Link.State.ACTIVE) {
                    nodes.add(link.getNode());
                }
            }
        }
    }

    private Bucket[] mBuckets = new Bucket[BUCKET_COUNT];
    private LocalNode mLocalNode;

    public NodeTracker(LocalNode localNode) {
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

    /**
     * Open a new link channel to a peer.
     *
     * This method is intentionally package-private.
     *
     * @param node
     */
    void openLink(final PeerNode node, CounterTrigger trigger) {
        Link link = new Link(this, node);
        link.setTrigger(trigger);
        getBucket(node).addLink(link);
    }

    /**
     * Handle a new link channel opened by a peer.
     *
     * This method is intentionally package-private.
     *
     * @param channel
     * @param channelPacket
     */
    void acceptLink(Channel channel, ChannelPacket channelPacket) {
        Log.i("DHT XXX: handleLink() channel: "+channel);
        Link link = new Link(this, channel, channelPacket);
        getBucket(channel.getRemoteNode()).addLink(link);
    }

    /** intentionally package-private */
    void onLinkActive(Link link) {
        getBucket(link.getNode()).addLink(link);
    }

    /** intentionally package-private */
    void onLinkClose(Link link) {
        getBucket(link.getNode()).removeLink(link);
    }

    private Bucket getBucket(Node node) {
        int distance = mLocalNode.getHashName().distanceMagnitude(node.getHashName());
        if (distance == -1) {
            // the referenced node is us.
            return null;
        }
        return mBuckets[distance];
    }

    public void submitNode(final Node node) {
        Telehash.get().getSwitch().getLineManager()
                .openLine(node, false, new CompletionHandler<Line>() {
                    @Override
                    public void completed(Line result, Object attachment) {
                        openLink(result.getRemotePeerNode(), null);
                    }
                    @Override
                    public void failed(Throwable exc, Object attachment) {
                        Log.w("cannot open link to node "+node+":", exc);
                    }
                }, null);
    }

    /*
    public void submitNode(PeerNode node) {
        int distance = mLocalNode.getHashName().distanceMagnitude(node.getHashName());
        if (distance == -1) {
            // the referenced node is us.
            return;
        }
        Bucket bucket = mBuckets[distance];
        bucket.submitNode(node);
    }
    */

    /*
    public void removeNode(PeerNode node) {
        int distance = mLocalNode.getHashName().distanceMagnitude(node.getHashName());
        if (distance == -1) {
            // the referenced node is us.
            return;
        }
        Bucket bucket = mBuckets[distance];
        bucket.removeNode(node);
    }
    */

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
                mBuckets[i].accumulateActiveNodes(sortedNodes);
            }
        } else {
            // the target node is not ourself -- scan the target bucket
            // first, followed by closer buckets, followed by farther buckets.

            // scan the target bucket
            mBuckets[startingBucket].accumulateActiveNodes(sortedNodes);

            // scan closer buckets
            for (int i = (startingBucket - 1); i >= 0 && sortedNodes.size() < maxNodes; i--) {
                mBuckets[i].accumulateActiveNodes(sortedNodes);
            }

            // scan farther buckets
            for (int i = (startingBucket + 1);
                    i < BUCKET_COUNT && sortedNodes.size() < maxNodes;
                    i++) {
                mBuckets[i].accumulateActiveNodes(sortedNodes);
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
    public void refreshBuckets(final Runnable completionHandler) {
        Log.i("perform self-seek");
        NodeLookupTask lookup = new NodeLookupTask(
                Telehash.get(),
                this,
                mLocalNode.getHashName(),
                new NodeLookupTask.Handler() {
                    @Override
                    public void handleError(NodeLookupTask task, Throwable e) {
                        Log.e("error performing self-seek", e);
                        completionHandler.run();
                    }

                    @Override
                    public void handleCompletion(NodeLookupTask task, Node self) {
                        Log.i("self-seek finished: "+self);
                        if (self == null) {
                            Log.e("could not seek self!  aborting refresh");
                            completionHandler.run();
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

                        // prepare to refresh individual buckets.

                        // use a CounterAlarm to signal completion when all of the
                        // individual bucket refreshes have completed.
                        CounterTrigger alarm = new CounterTrigger(completionHandler);

                        int bucketRefreshCount = 0;
                        long now = System.nanoTime();
                        for (int i=neighborDistance; i<BUCKET_COUNT; i++) {
                            Log.i("considering bucket["+i+"] of size="+mBuckets[i].size()
                                    +": "+mBuckets[i]);
                            if (mBuckets[i].mLastNodeLookupTime == -1 ||
                                    ((now - mBuckets[i].mLastNodeLookupTime) >
                                    BUCKET_REFRESH_TIME_NS)) {
                                refreshBucket(alarm, i);
                                bucketRefreshCount++;
                            }
                        }
                        alarm.setLimit(bucketRefreshCount);
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
    private void refreshBucket(final CounterTrigger alarm, final int bucket) {
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
                        alarm.signal();
                    }

                    @Override
                    public void handleCompletion(NodeLookupTask task, Node result) {
                        Log.i("bucket[%d] refreshed.", bucket);
                        alarm.signal();
                    }
                }
        );
        lookup.start();
    }

    public void dump() {
        StringBuilder sb = new StringBuilder();
        sb.append("DHT tracking "+size()+" nodes:\n");
        for (int i=0; i<BUCKET_COUNT; i++) {
            if (mBuckets[i].size() > 0) {
                sb.append("    ["+i+"] ");
                for (Link link : mBuckets[i].mLinks) {
                    sb.append(link+" ");
                }
                sb.append("\n");
            }
        }
        Log.d(sb.toString());
    }
}
