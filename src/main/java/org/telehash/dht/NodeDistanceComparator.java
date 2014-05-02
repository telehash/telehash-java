package org.telehash.dht;

import org.telehash.core.HashName;
import org.telehash.core.Node;

import java.math.BigInteger;
import java.util.Comparator;

class NodeDistanceComparator implements Comparator<Node> {
    private HashName mTargetHashName;
    public NodeDistanceComparator(HashName targetHashName) {
        mTargetHashName = targetHashName;
    }
    @Override
    public int compare(Node a, Node b) {
        BigInteger da = mTargetHashName.distance(a.getHashName());
        BigInteger db = mTargetHashName.distance(b.getHashName());
        return da.compareTo(db);
    }
}