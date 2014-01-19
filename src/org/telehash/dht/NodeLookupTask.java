package org.telehash.dht;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.telehash.core.HashName;
import org.telehash.core.Log;
import org.telehash.core.Node;
import org.telehash.core.Telehash;

public class NodeLookupTask {
    
    /**
     * The Kademlia "query concurrency parameter", represented in the paper as
     * alpha.
     */
    private static final int QUERY_CONCURRENCY_PARAMETER = 3;
    
    /**
     * The Kademlia "k closest nodes" parameter. Since we're only using Kademlia
     * as a key-based routing scheme and not a full storage-capable DHT, our
     * goals are a bit different -- we really want the *exact* node eventually,
     * and not a set of close nodes that may be storing a particular DHT
     * key/value pair. However, having a closeness parameter is required for the
     * Kademlia node lookup algorithm to work.
     */
    private static final int CLOSENESS = 9;
    
    private Telehash mTelehash;
    private NodeTracker mNodeTracker;
    private HashName mTargetHashName;
    
    private SortedSet<Node> mQueryNodes;
    private SortedSet<Node> mVisitedNodes;
    private Set<NodeSeekRequest> mOutstandingSeeks = new HashSet<NodeSeekRequest>();
    private int mIterations = 0;
    private Node mClosestNode = null;
    private BigInteger mClosestNodeDistance = null;
    
    public static interface Handler {
        void handleError(NodeLookupTask task, Throwable e);
        void handleCompletion(NodeLookupTask task, Node result);
    }
    private Handler mHandler;
    
    public NodeLookupTask(Telehash telehash, NodeTracker nodeTracker, HashName targetHashName, Handler handler) {
        mTelehash = telehash;
        mNodeTracker = nodeTracker;
        mTargetHashName = targetHashName;
        mHandler = handler;
        
        mQueryNodes = new TreeSet<Node>(new NodeDistanceComparator(mTargetHashName));
        mVisitedNodes = new TreeSet<Node>(new NodeDistanceComparator(mTargetHashName));
    }
    
    public Node getClosestVisitedNode() {
        return mVisitedNodes.first();
    }
    
    public Node getFarthestVisitedNode() {
        return mVisitedNodes.last();
    }

    public void start() {
        // start with the set of nodes in our tracker that are closest to the target.
        Log.i("tracked nodes = "+mNodeTracker.size());
        mQueryNodes.addAll(mNodeTracker.getClosestNodes(mTargetHashName, CLOSENESS));
        Log.i("adding initial query nodes = "+mNodeTracker.getClosestNodes(mTargetHashName, CLOSENESS));
        iterate();
    }
    
    private void iterate() {
        Log.d("node lookup iteration");
        Log.d("  querynodes="+mQueryNodes);
        Log.d("  visitednodes="+mVisitedNodes);
        // remove already visited nodes from our set of queryable nodes
        mQueryNodes.removeAll(mVisitedNodes);
        
        // if there are no queryable nodes, signal completion
        if (mQueryNodes.isEmpty()) {
            Log.d("node lookup complete: no queryable nodes.");
            complete(null);
            return;
        }
        
        // if the target node is present in our set, signal completion
        if (mTargetHashName.equals(mQueryNodes.first().getHashName())) {
            Log.d("node lookup complete: "+mQueryNodes.first());
            complete(mQueryNodes.first());
            return;
        }
        
        // if there are no closer nodes available after a "round", complete.
        if (mIterations > 0 && mClosestNode != null && (mIterations % QUERY_CONCURRENCY_PARAMETER) == 0) {
            BigInteger distanceToClosestQueryNode = mQueryNodes.first().getHashName().distance(mTargetHashName);
            if (distanceToClosestQueryNode.compareTo(mClosestNodeDistance) >= 0) {
                Log.d("node lookup complete: converged");
                complete(null);
                return;
            }
        
            // record the closest node yet discovered
            Node candidate = null;
            BigInteger candidateDistance = null;
            if (! mVisitedNodes.isEmpty()) {
                candidate = mVisitedNodes.first();
                candidateDistance = candidate.getHashName().distance(mTargetHashName);
            }
            if (candidate == null) {
                candidate = mQueryNodes.first();
                candidateDistance = candidate.getHashName().distance(mTargetHashName);
            } else {
                BigInteger dq = mQueryNodes.first().getHashName().distance(mTargetHashName);
                if (dq.compareTo(candidateDistance) < 0) {
                    candidate = mQueryNodes.first();
                    candidateDistance = dq;
                }
            }
            if (mClosestNode != null) {
                BigInteger dp = mClosestNode.getHashName().distance(mTargetHashName);
                if (dp.compareTo(candidateDistance) < 0) {
                    candidate = mClosestNode;
                    candidateDistance = dp;
                }
            }
            mClosestNode = candidate;
            mClosestNodeDistance = candidateDistance;
        }

        // make a copy of the nodes to query, so we can safely append to mQueryNodes
        // from within the iteration
        int additionalRequestsNeeded = QUERY_CONCURRENCY_PARAMETER - mOutstandingSeeks.size();
        int seeks=0;
        List<Node> currentQueryNodes = new ArrayList<Node>(additionalRequestsNeeded);
        for (Node queryNode : mQueryNodes) {
            currentQueryNodes.add(queryNode);
            seeks++;
            if (seeks >= additionalRequestsNeeded) {
                break;
            }            
        }
        
        // provision/start the additional seek requests.
        for (Node queryNode : currentQueryNodes) {
            final NodeSeekRequest seek =
                    new NodeSeekRequest(mTelehash, queryNode, mTargetHashName, new NodeSeekRequest.Handler() {
                        // TODO: resource usage could be reduced by making this class shared
                        //       among all seeks, instead of a separate Handler for each.
                        @Override
                        public void handleError(NodeSeekRequest seek, Throwable e) {
                            Log.i("error during seek");
                            e.printStackTrace();
                            mOutstandingSeeks.remove(seek);
                            iterate();
                        }
                        @Override
                        public void handleCompletion(NodeSeekRequest seek) {
                            Log.i("seek complete");
                            mOutstandingSeeks.remove(seek);
                            // if we want to track nodes that we don't have a public key for yet,
                            // uncomment this.
                            /*
                            for (Node node : seek.getResultNodes()) {
                                // track this encountered node
                                mNodeTracker.submitNode(node);
                            }
                            */
                            mQueryNodes.addAll(seek.getResultNodes());
                            iterate();
                        }
                    });
            mOutstandingSeeks.add(seek);
            mVisitedNodes.add(queryNode);
            seek.start();
        }
        
        mIterations++;
    }
    
    private void fail(Throwable e) {
        Log.i("node lookup failure: "+e);
        if (mHandler != null) {
            mHandler.handleError(this, e);
        }
    }
    
    private void complete(Node node) {
        if (mHandler != null) {
            mHandler.handleCompletion(this, node);
        }
    }
}
