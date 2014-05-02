package org.telehash.core;

public class PlaceholderNode extends Node {
    public PlaceholderNode(final HashName hashName) {
        super(hashName);
    }

    @Override
    public String toString() {
        String hashName = mHashName.getShortHash();
        return "Node["+hashName+"]";
    }

}
