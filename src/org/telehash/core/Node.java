package org.telehash.core;

/**
 * This abstract class represents a Telehash node, including its
 * hashname and any public keys, fingerprints, and network paths we may
 * be aware of.
 *
 * <p>
 * The data associated with a node varies throughout the Telehash
 * protocol and the operation of the switch, due to various steps having
 * incomplete information about the possible fields: private keys,
 * public keys, fingerprints, hashname, supported cipher sets, and
 * network paths. This information may be represented by various
 * subclasses:
 * </p>
 *
 * <ol>
 * <li>A PlaceholderNode object only contains a hashname, and is used to
 * refer to nodes before a public key and compatible cipher set has been
 * determined. When connecting to a PlaceholderNode, a DHT node lookup
 * must be performed to discover a common peer willing to introduce us
 * via peer/connect.</li>
 * <li>A SeeNode object represents a "see" line provided to us in
 * response to a node lookup. This object contains a single public key
 * corresponding to the best cipher set that the common peer has
 * determined we should use, and a reference to a referring PeerNode
 * which may be used to introduce us via peer/connect. The SeeNode
 * object may also contain a single network path for hole punching.</li>
 * <li>PeerNode objects are the most commonly used node representations
 * in Telehash. A PeerNode object represents a peer for whom we have
 * enough information to directly communicate with -- a set of
 * fingerprints, a valid public key in the best mutually supported
 * cipher set, and one or more network paths.</li>
 * <li>The FullNode abstract class represents a node for whom we have
 * full knowledge of its supported cipher sets and all available public
 * keys. FullNode subclasses are used to represent the local node and
 * any seeds we've read from a seeds.json file.</li>
 * <li>A SeedNode is a node obtained from a seeds.json file. We have
 * full public key and network path information about these nodes.</li>
 * <li>A switch owns a single LocalNode object which contains the public
 * and private key pairs for all supported cipher sets, from which its
 * fingerprints, hashname, and supported cipher sets may be derived. A
 * switch may have partial knowledge of its network paths as obtained by
 * enumerating the local network interfaces, which may be augmented
 * later if a different public network path (e.g. at a NAT router) is
 * discovered.</li>
 */
public abstract class Node {

    protected final HashName mHashName;

    protected Node(final HashName hashName) {
        mHashName = hashName;
    }

    public HashName getHashName() {
        return mHashName;
    }

    // Java identity

    @Override
    public boolean equals(Object other) {
        if (    other != null &&
                other instanceof Node &&
                ((Node)other).getHashName().equals(mHashName)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return mHashName.hashCode();
    }
}