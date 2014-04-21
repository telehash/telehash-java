package org.telehash.core;

import org.telehash.dht.DHT;
import org.telehash.dht.NodeLookupTask;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class LineManager {

    private Telehash mTelehash;

    private static class LineTracker {
        private Map<HashName,Line> mHashNameToLineMap = new HashMap<HashName,Line>();
        private Map<Node,Line> mNodeToLineMap = new HashMap<Node,Line>();
        private Map<LineIdentifier,Line> mIncomingLineIdentifierToLineMap =
                new HashMap<LineIdentifier,Line>();
        public Line getByNode(Node node) {
            return mNodeToLineMap.get(node);
        }
        public Line getByHashName(HashName hashName) {
            return mHashNameToLineMap.get(hashName);
        }
        public Line getByIncomingLineIdentifier(LineIdentifier lineIdentifier) {

            // TODO: remove this debugging block
            StringBuilder sb = new StringBuilder();
            if (mIncomingLineIdentifierToLineMap.get(lineIdentifier) == null) {
                if (mIncomingLineIdentifierToLineMap.containsKey(lineIdentifier)) {
                    sb.append("XXX has key, but value is null\n");
                } else {
                    sb.append("XXX cannot find "+
                            lineIdentifier+" ; candidates include:\n");
                    for (LineIdentifier id : mIncomingLineIdentifierToLineMap.keySet()) {
                        sb.append("XXX     "+id+" "+(id != null ? id.hashCode() : "null")+"\n");
                    }
                }
            }
            Log.i(sb.toString());

            return mIncomingLineIdentifierToLineMap.get(lineIdentifier);
        }
        public void add(Line line) {
            Log.i("tracking line: "+line);
            if (mNodeToLineMap.containsKey(line.getRemoteNode())) {
                // put() would overwrite, but we must make sure to
                // remove the entry from both maps.
                Line oldLine = mNodeToLineMap.get(line.getRemoteNode());
                mHashNameToLineMap.remove(oldLine.getRemoteNode().getHashName());
                mNodeToLineMap.remove(oldLine.getRemoteNode());
                mIncomingLineIdentifierToLineMap.remove(oldLine.getIncomingLineIdentifier());
            }
            mHashNameToLineMap.put(line.getRemoteNode().getHashName(), line);
            mNodeToLineMap.put(line.getRemoteNode(), line);
            mIncomingLineIdentifierToLineMap.put(line.getIncomingLineIdentifier(), line);
            Log.i(toString());
        }
        public void remove(Line line) {
            Log.i("removing line: "+line+" // inc="+line.getIncomingLineIdentifier()+" out="+line.getOutgoingLineIdentifier()+" node="+line.getRemoteNode());
            mHashNameToLineMap.remove(line.getRemoteNode().getHashName());
            mNodeToLineMap.remove(line.getRemoteNode());
            mIncomingLineIdentifierToLineMap.remove(line.getIncomingLineIdentifier());
            Log.i(toString());
        }
        public Collection<Line> getLines() {
            return mNodeToLineMap.values();
        }
        // TODO: purge()

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(""+mNodeToLineMap.size()+" nodes in line tracker:\n");
            int i=0;
            for (Map.Entry<Node, Line> entry : mNodeToLineMap.entrySet()) {
                sb.append("\t"+String.format("%02d",i++)+">> ");
                Node node = entry.getKey();
                Line line = entry.getValue();
                sb.append(node.getHashName().asHex()+" ");
                if (line.getIncomingLineIdentifier() == null) {
                    sb.append("null ");
                } else {
                    sb.append(line.getIncomingLineIdentifier()+" ");
                }
                if (line.getOutgoingLineIdentifier() == null) {
                    sb.append("null ");
                } else {
                    sb.append(line.getOutgoingLineIdentifier()+" ");
                }
                sb.append(line.getState().name()+" ");
                //sb.append(node.getPath()+"\n");
                sb.append("\n");
            }
            return sb.toString();
        }
    }
    private LineTracker mLineTracker = new LineTracker();

    ////////////////////////////////////////////////////////////

    public LineManager(Telehash telehash) {
        mTelehash = telehash;
    }

    public void init() {

    }

    public void dump() {
        Log.i(mLineTracker.toString());
    }

    public void openChannel(
            PeerNode destination,
            final String type,
            final ChannelHandler channelHandler
    ) throws TelehashException {
        CompletionHandler<Line> lineOpenCompletionHandler = new CompletionHandler<Line>() {
            @Override
            public void completed(Line line, Object attachment) {
                line.openChannel(type, channelHandler);
            }

            @Override
            public void failed(Throwable throwable, Object attachment) {
                channelHandler.handleError(null, throwable);
            }
        };

        // open a new line (or re-use an existing line)
        openLine(destination, false, lineOpenCompletionHandler, null);
    }

    public void sendLinePacket(
            Line line,
            ChannelPacket channelPacket,
            CompletionHandler<Line> handler,
            Object attachment
    ) throws TelehashException {
        // create a line packet
        LinePacket linePacket = new LinePacket(line, channelPacket);
        mTelehash.getSwitch().sendPacket(linePacket);
    }

    private void calculateLineKeys(Line line, OpenPacket incomingOpen, OpenPacket outgoingOpen) {
        // calculate ECDH
        byte[] sharedSecret = line.getCipherSet().calculateECDHSharedSecret(
                incomingOpen.getLinePublicKey(),
                outgoingOpen.getLinePrivateKey()
        );
        line.setSharedSecret(sharedSecret);
        // The encryption key for a line is defined as the SHA 256 digest of
        // the ECDH shared secret (32 bytes) + outgoing line id (16 bytes) +
        // incoming line id (16 bytes). The decryption key is the same
        // process, but with the outgoing/incoming line ids reversed.
        line.setEncryptionKey(
                mTelehash.getCrypto().sha256Digest(
                        Util.concatenateByteArrays(
                                sharedSecret,
                                line.getIncomingLineIdentifier().getBytes(),
                                line.getOutgoingLineIdentifier().getBytes()
                        )
                )
        );
        line.setDecryptionKey(
                mTelehash.getCrypto().sha256Digest(
                        Util.concatenateByteArrays(
                                sharedSecret,
                                line.getOutgoingLineIdentifier().getBytes(),
                                line.getIncomingLineIdentifier().getBytes()
                        )
                )
        );
    }

    ////////////////////////////////////////////////////////////
    // methods that proxy to the line tracker
    ////////////////////////////////////////////////////////////

    // intentionally package-private
    void clearLine(Line line) {
        mLineTracker.remove(line);
    }

    public Line getLineByNode(PeerNode node) {
        return mLineTracker.getByNode(node);
    }

    public Line getLineByHashName(HashName hashName) {
        return mLineTracker.getByHashName(hashName);
    }

    public Line getLine(LineIdentifier lineIdentifier) {
        return mLineTracker.getByIncomingLineIdentifier(lineIdentifier);
    }

    public Set<Line> getLines() {
        return Line.sortByOpenTime(mLineTracker.getLines());
    }

    ////////////////////////////////////////////////////////////
    // line establishment and negotiation methods
    ////////////////////////////////////////////////////////////

    public void openLine(
            Node destination,
            boolean reopen,
            CompletionHandler<Line> handler,
            Object attachment
    ) {
        Log.i("openLine destination="+destination+" reopen="+reopen);

        // NOTE: if this is called twice, the latter call supersedes the
        // previous line entry.  Perhaps instead we should throw an exception,
        // or simply return the current line.

        // if a line is already open to this node, re-use the same line by
        // simply adding the provided completion handler.
        Line existingLine = mLineTracker.getByNode(destination);
        if (existingLine != null) {
            if (reopen) {
                // if we are superseding an existing line, fail the existing line to
                // notify interested parties, cancel timeouts, etc.
                existingLine.fail(new TelehashException("line reset"));
            } else if (! reopen) {
                // if the line is PENDING, the handler will be called with the line is ESTABLISHED.
                // if the line is ESTABLISHED, the handler will be called immediately.
                existingLine.addOpenCompletionHandler(handler, null);
                return;
            }
        }

        // create a line, an outgoing open packet, and record these in the line tracker
        final Line line = new Line(mTelehash);
        line.setRemoteNode(destination);
        line.addOpenCompletionHandler(handler, attachment);

        // generate a random line identifier
        // (it's an *incoming* line identifier, but will be provided in the *outgoing* open.)
        line.setIncomingLineIdentifier(LineIdentifier.generate());

        Log.i("tracking line "+line+" due to openLine()");
        mLineTracker.add(line);

        // Determine if this is a direct line open, or a reverse line open.
        // We can open lines directly if we know the node's network path
        // and public key (i.e. if the node is a seed in our seeds.json,
        // or we have been asked to initiate an open to this node via
        // peer/connect).  Otherwise, we must ask the referring node to
        // introduce us via peer/connect.
        if (destination instanceof PeerNode) {
            if (((PeerNode) destination).getPath() == null) {
                line.fail(new TelehashException("peer node has no path!"));
                return;
            }
            openLineDirect(line);
        } else if (destination instanceof SeeNode) {
            SeeNode see = (SeeNode)destination;
            PeerNode referringNode = see.getReferringNode();
            openLineReverse(line, referringNode);
        } else if (destination instanceof PlaceholderNode) {
            openLineReverseWithNodeLookup(line);
        } else {
            line.fail(new TelehashException("unknown node type"));
            return;
        }
    }

    public void openLineDirect(Line line) {
        // The destination is always a PeerNode if this method is called.
        PeerNode destination = (PeerNode)line.getRemoteNode();

        // determine the best cipher set which is common between our two nodes
        CipherSetIdentifier csid = destination.getActiveCipherSetIdentifier();
        if (csid == null) {
            line.fail(new TelehashException("no common cipher set with the remote node"));
            return;
        }
        line.setCipherSetIdentifier(csid);

        // formulate the outgoing open packet
        OpenPacket openPacket = new OpenPacket(
                mTelehash.getLocalNode(),
                destination,
                line.getCipherSet().getCipherSetId(),
                line.getIncomingLineIdentifier()
        );
        // note: this open packet is *outgoing* but its embedded line identifier
        // is to be used for *incoming* line packets.
        line.setLocalOpenPacket(openPacket);

        line.setState(Line.State.DIRECT_OPEN_PENDING);
        line.startOpenTimer();

        // enqueue the packet to be sent
        try {
            mTelehash.getSwitch().sendPacket(line.getLocalOpenPacket());
        } catch (RuntimeException e) {
            mLineTracker.remove(line);
            line.fail(new TelehashException(e));
        } catch (TelehashException e) {
            mLineTracker.remove(line);
            line.fail(new TelehashException(e));
        }
    }

    private void openLineReverse(
            final Line line,
            final PeerNode referringNode
    ) {
        // The destination is always a SeeNode if this method is called.
        SeeNode destination = (SeeNode)line.getRemoteNode();

        // determine the best cipher set which is common between our two nodes
        CipherSetIdentifier csid = destination.getCipherSetIdentifier();
        if (csid == null) {
            line.fail(new TelehashException("no common cipher set with the remote node"));
            return;
        }
        line.setCipherSetIdentifier(csid);

        Line referringLine = getLineByNode(referringNode);
        if (referringLine == null) {
            mLineTracker.remove(line);
            line.fail(new TelehashException("no line to referring node: "+referringNode));
            return;
        }

        line.setState(Line.State.REVERSE_OPEN_PENDING);
        line.startOpenTimer();

        referringLine.openChannel(DHT.PEER_TYPE, new ChannelHandler() {
            @Override
            public void handleError(Channel channel, Throwable error) {
                mLineTracker.remove(line);
                line.fail(error);
            }
            @Override
            public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
                // do nothing -- there is no response expected
            }
            @Override
            public void handleOpen(Channel channel) {
                Map<String,Object> fields = new HashMap<String,Object>();
                fields.put(DHT.PEER_KEY, line.getRemoteNode().getHashName().asHex());
                // TODO: if we have multiple public (non-site-local) paths, they
                // should be indicated in a "paths" key.
                try {
                    channel.send(null, fields, true);
                } catch (TelehashException e) {
                    mLineTracker.remove(line);
                    line.fail(e);
                    return;
                }
            }
        });
    }

    private void openLineReverseWithNodeLookup(final Line line) {
        line.setState(Line.State.NODE_LOOKUP);

        mTelehash.getSwitch().getDHT().nodeLookup(
                line.getRemoteNode().getHashName(),
                new NodeLookupTask.Handler() {
                    @Override
                    public void handleError(NodeLookupTask task, Throwable e) {
                        mLineTracker.remove(line);
                        line.fail(e);
                    }
                    @Override
                    public void handleCompletion(NodeLookupTask task, Node resultNode) {
                        // if no nodes could be found, error out
                        if (resultNode == null) {
                            mLineTracker.remove(line);
                            line.fail(new TelehashException("node not found"));
                            return;
                        }

                        // replace the line's placeholder node with the lookup result
                        line.setRemoteNode(resultNode);

                        // the result of a node lookup should be either a SeeNode
                        // or a PeerNode.
                        if (resultNode instanceof SeeNode) {
                            SeeNode see = (SeeNode)resultNode;
                            openLineReverse(line, see.getReferringNode());
                        } else if (resultNode instanceof PeerNode) {
                            openLineDirect(line);
                        } else {
                            mLineTracker.remove(line);
                            line.fail(new TelehashException("lookup returned unknown type"));
                            return;
                        }
                    }
                }
        );
    }

    /** intentionally package-private */
    void handleOpenPacket(OpenPacket incomingOpenPacket) throws TelehashException {

        Log.i("OPEN received from: "+incomingOpenPacket.getSourceNode());

        // is there a pending line for this?
        PeerNode remoteNode = incomingOpenPacket.getSourceNode();
        Line line = mLineTracker.getByNode(remoteNode);
        if (line != null && line.getState() == Line.State.DIRECT_OPEN_PENDING && (
                line.getOutgoingLineIdentifier() == null ||
                line.getOutgoingLineIdentifier().equals(incomingOpenPacket.getLineIdentifier())
        )) {
            // an existing line is present for this open.

            if (line.getState() == Line.State.ESTABLISHED) {
                // this line is already established -- this open packet
                // is redundant.
                return;
            }

            line.setRemoteOpenPacket(incomingOpenPacket);
            line.setOutgoingLineIdentifier(incomingOpenPacket.getLineIdentifier());
            calculateLineKeys(line, incomingOpenPacket, line.getLocalOpenPacket());
            line.completeOpen();
            Log.i("new line established for local initiator");
        } else {
            // The remote node is initiating a line to us.  (Perhaps because we asked
            // for an introduction via peer/connect.)  Prepare a response open packet.
            OpenPacket replyOpenPacket;
            if (line != null && line.getState() == Line.State.REVERSE_OPEN_PENDING) {
                // a reverse-open is pending; create an open packet for it.
                replyOpenPacket = new OpenPacket(
                        mTelehash.getLocalNode(),
                        incomingOpenPacket.getSourceNode(),
                        incomingOpenPacket.getCipherSet().getCipherSetId(),
                        line.getIncomingLineIdentifier()
                );
                // note: this open packet is *outgoing* but its embedded line identifier
                // is to be used for *incoming* line packets.
                Log.i("\tmatches existing line: "+line);
                Log.i("\topenPacket.lineid="+replyOpenPacket.getLineIdentifier());
                line.setIncomingLineIdentifier(replyOpenPacket.getLineIdentifier());
                line.setLocalOpenPacket(replyOpenPacket);
                Log.i("\tline remote node was: "+line.getRemoteNode());
                line.setRemoteNode(incomingOpenPacket.getSourceNode());
                Log.i("\tline remote node now: "+line.getRemoteNode());
                Log.i("\tnew line established for remote initiator (reverse)");
                dump();
            } else {
                // create a new open package and line.
                LineIdentifier incomingLineIdentifier = LineIdentifier.generate();
                replyOpenPacket = new OpenPacket(
                        mTelehash.getLocalNode(),
                        incomingOpenPacket.getSourceNode(),
                        incomingOpenPacket.getCipherSet().getCipherSetId(),
                        incomingLineIdentifier
                );
                line = new Line(mTelehash);
                line.setCipherSetIdentifier(incomingOpenPacket.getCipherSet().getCipherSetId());
                line.setIncomingLineIdentifier(incomingLineIdentifier);
                line.setLocalOpenPacket(replyOpenPacket);
                line.setRemoteNode(incomingOpenPacket.getSourceNode());
                mLineTracker.add(line);
                Log.i("new line established for remote initiator");
            }

            // perform the "pre-render" stage so values such as the EC key pair
            // have been generated.
            replyOpenPacket.preRender();

            // update the Line with information from the remote node's open packet.
            // note: this reply open packet is *outgoing* but its embedded line identifier
            // is to be used for *incoming* line packets.
            line.setRemoteOpenPacket(incomingOpenPacket);
            line.setOutgoingLineIdentifier(incomingOpenPacket.getLineIdentifier());

            // perform ECDH
            calculateLineKeys(line, incomingOpenPacket, replyOpenPacket);

            // TODO: discard open packets after line establishment?

            // TODO: alert interested parties of the new line?

            // alert the DHT of the new line
            // TODO: this should be abstracted into some sort of LineObserver
            mTelehash.getSwitch().getDHT().handleNewLine(line);

            // enqueue the packet to be sent
            try {
                mTelehash.getSwitch().sendPacket(replyOpenPacket);
                line.completeOpen(); // line is now ESTABLISHED.
            } catch (RuntimeException e) {
                mLineTracker.remove(line);
                line.fail(e);
            } catch (TelehashException e) {
                mLineTracker.remove(line);
                line.fail(e);
            }
        }
    }
}
