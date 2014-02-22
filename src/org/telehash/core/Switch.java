package org.telehash.core;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.telehash.dht.DHT;
import org.telehash.network.Datagram;
import org.telehash.network.DatagramHandler;
import org.telehash.network.InetPath;
import org.telehash.network.Path;
import org.telehash.network.Reactor;

/**
 * The Switch class is the heart of Telehash. The switch is responsible for
 * managing identity and node information, maintaining the DHT, and facilitating
 * inter-node communication.
 */
public class Switch implements DatagramHandler {
    
    private static final int DEFAULT_PORT = 42424;

    private Telehash mTelehash;
    private Set<Node> mSeeds;
    private int mPort;
    private Reactor mReactor;
    private Thread mThread;
    private Object mStopLock = new Object();
    
    private boolean mStopRequested = false;
    
    private Node mLocalNode;
    private DHT mDHT;
    private Scheduler mScheduler = new Scheduler();
    private Map<HashName,PendingReverseOpen> mPendingReverseOpens =
            new HashMap<HashName,PendingReverseOpen>();
    
    private static class PendingReverseOpen {
        public HashName destination;
        public CompletionHandler<Line> completionHandler;
        public Object attachment;
    }
    
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
            if (mIncomingLineIdentifierToLineMap.get(lineIdentifier) == null) {
                if (mIncomingLineIdentifierToLineMap.containsKey(lineIdentifier)) {
                    Log.i("XXX has key, but value is null");
                } else {
                    Log.i("XXX cannot find "+
                            lineIdentifier+" ; candidates include:");
                    for (LineIdentifier id : mIncomingLineIdentifierToLineMap.keySet()) {
                        Log.i("XXX     "+id+" "+id.hashCode());
                    }
                }
            }
            
            return mIncomingLineIdentifierToLineMap.get(lineIdentifier);
        }
        public void add(Line line) {
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
        }
        public void remove(Line line) {
            mHashNameToLineMap.remove(line.getRemoteNode().getHashName());
            mNodeToLineMap.remove(line.getRemoteNode());
            mIncomingLineIdentifierToLineMap.remove(line.getIncomingLineIdentifier());
        }
        public Collection<Line> getLines() {
            return mNodeToLineMap.values();
        }
        // TODO: purge()
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(""+mNodeToLineMap.size()+" nodes in line tracker:\n");
            for (Map.Entry<Node, Line> entry : mNodeToLineMap.entrySet()) {
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
                sb.append(node.getPath()+"\n");
            }
            return sb.toString();
        }
    }
    private LineTracker mLineTracker = new LineTracker();

    public Switch(Telehash telehash, Set<Node> seeds) {
        mTelehash = telehash;
        mSeeds = seeds;
        mPort = DEFAULT_PORT;
    }

    public Switch(Telehash telehash, Set<Node> seeds, int port) {
        mTelehash = telehash;
        mSeeds = seeds;
        mPort = port;
    }

    public void start() throws TelehashException {

        // determine the local node information
        Path localPath = mTelehash.getNetwork().getPreferredLocalPath();
        if (localPath == null) {
            throw new TelehashException("no network");
        }
        if (! (localPath instanceof InetPath)) {
            throw new TelehashException("local network is not IP.");
        }
        InetPath inetPath = (InetPath)localPath;
        inetPath = new InetPath(inetPath.getAddress(), mPort);
        mLocalNode = new Node(mTelehash.getIdentity().getPublicKey(), inetPath);
        
        // provision the reactor
        mReactor = mTelehash.getNetwork().createReactor(mPort);
        mReactor.setDatagramHandler(this);
        try {
            mReactor.start();
        } catch (IOException e) {
            throw new TelehashException(e);
        }
        
        // launch thread
        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                mTelehash.setThreadLocal();
                loop();
            }
        });
        mThread.start();
    }
    
    public void stop() {
        synchronized (mStopLock) {
            if (mReactor != null) {
                mReactor.stop();
                mStopRequested = true;
                
                if (! Thread.currentThread().equals(mThread)) {
                    // wait for loop to finish
                    try {
                        mStopLock.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }
    
    public Line getLine(LineIdentifier lineIdentifier) {
        return mLineTracker.getByIncomingLineIdentifier(lineIdentifier);
    }
    
    public Set<Line> getLines() {
        return Line.sortByOpenTime(mLineTracker.getLines());
    }
    
    public void openChannel(Node destination, final String type, final ChannelHandler channelHandler) throws TelehashException {
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
        
        Line line = mLineTracker.getByNode(destination);
        if (line == null) {
            // open a new line
            openLine(destination, lineOpenCompletionHandler, null);
        } else {
            // add our completion handler to the existing line.
            // if it is PENDING, the handler will be called with the line is ESTABLISHED.
            // if it is ESTABLISHED, the handler will be called immediately.
            line.addOpenCompletionHandler(lineOpenCompletionHandler, null);
        }
    }
    
    // TODO: timeout?
    public void openLine(
            Node destination,
            CompletionHandler<Line> handler,
            Object attachment
    ) throws TelehashException {
        // NOTE: if this is called twice, the latter call supersedes the
        // previous line entry.  Perhaps instead we should throw an exception,
        // or simply return the current line.
        
        // if we don't know the public key of the destination node, we must
        // ask the referring node to introduce us.
        if (destination.getPublicKey() == null) {
            Node referringNode = destination.getReferringNode();
            if (referringNode == null) {
                throw new TelehashException(
                        "cannot open a line to a node with an " +
                        "unknown public key and no referring node."
                );
            }
            reverseOpenLine(referringNode, destination, handler, attachment);
            return;
        }
        
        // create an open packet
        OpenPacket openPacket = new OpenPacket(mTelehash.getIdentity(), destination);
        
        // create and record a line entry
        Line line = new Line(mTelehash);
        // note: this open packet is *outgoing* but its embedded line identifier
        // is to be used for *incoming* line packets.
        Log.i("openPacket.lineid="+openPacket.getLineIdentifier());
        line.setIncomingLineIdentifier(openPacket.getLineIdentifier());
        line.setLocalOpenPacket(openPacket);
        line.setRemoteNode(destination);
        line.setState(Line.State.PENDING);
        line.addOpenCompletionHandler(handler, attachment);
        
        // TODO: synchronize
        mLineTracker.add(line);
        
        // enqueue the packet to be sent
        try {
            sendPacket(openPacket);
            // TODO: wait for response?
        } catch (RuntimeException e) {
            // rollback
            mLineTracker.remove(line);
            throw e;
        } catch (TelehashException e) {
            mLineTracker.remove(line);
            throw e;            
        }        
    }
    
    public void reverseOpenLine(
            final Node referringNode,
            final Node destination,
            final CompletionHandler<Line> handler,
            final Object attachment
    ) throws TelehashException {
        Line line = getLineByNode(referringNode);
        if (line == null) {
            throw new TelehashException("no line to referring node");
        }
        line.openChannel("peer", new ChannelHandler() {
            @Override
            public void handleError(Channel channel, Throwable error) {
                if (handler != null) {
                    handler.failed(error, attachment);
                }
                mPendingReverseOpens.remove(destination.getHashName());
            }
            @Override
            public void handleIncoming(Channel channel, ChannelPacket channelPacket) {
                // do nothing -- there is no response expected
            }
            @Override
            public void handleOpen(Channel channel) {
                Map<String,Object> fields = new HashMap<String,Object>();
                fields.put("peer", destination.getHashName().asHex());
                // TODO: if we have multiple public (non-site-local) paths, they
                // should be indicated in a "paths" key.
                try {
                    channel.send(null, fields, true);
                } catch (TelehashException e) {
                    if (handler != null) {
                        handler.failed(e, attachment);
                    }
                    mPendingReverseOpens.remove(destination.getHashName());
                    return;
                }
                
                // track the reverse open
                PendingReverseOpen pendingReverseOpen = new PendingReverseOpen();
                pendingReverseOpen.destination = destination.getHashName();
                pendingReverseOpen.completionHandler = handler;
                pendingReverseOpen.attachment = attachment;
                mPendingReverseOpens.put(destination.getHashName(), pendingReverseOpen);                
            }
        });
    }
    
    public void sendLinePacket(
            Line line,
            ChannelPacket channelPacket,
            CompletionHandler<Line> handler,
            Object attachment
    ) throws TelehashException {
        // create a line packet
        LinePacket linePacket = new LinePacket(line, channelPacket);
        sendPacket(linePacket);
    }
    
    public void sendPacket(Packet packet) throws TelehashException {
        if (packet == null) {
            return;
        }
        Node destination = packet.getDestinationNode();
        Log.i("sending to hashname="+destination);
        Datagram datagram =
                new Datagram(packet.render(), null, packet.getDestinationNode().getPath());
        
        if (mReactor != null) {
            mReactor.sendDatagram(datagram);
        }
    }

    private void loop() {
        Log.i("switch loop with identity="+mTelehash.getIdentity()+" and seeds="+mSeeds);
        
        mDHT = new DHT(mTelehash, mLocalNode, mSeeds);
        mDHT.init();
        
        try {
            while (true) {
                long nextTaskTime = mScheduler.getNextTaskTime();
                if (nextTaskTime == -1) {
                    // hack: if any tasks are currently runnable, use a select timeout
                    // of 1ms and then run them.
                    nextTaskTime = 1;
                }
                
                // select and dispatch
                mReactor.select(nextTaskTime);
                
                // run any timed tasks
                mScheduler.runTasks();
                
                if (mStopRequested) {
                    break;
                }
            }
        } catch (IOException e) {
            Log.i("loop ending abnormaly");
            e.printStackTrace();
        } finally {
            try {
                mReactor.close();
            } catch (IOException e) {
                Log.i("error closing reactor.");
                e.printStackTrace();
            }
        }
        
        // signal loop completion
        synchronized (mStopLock) {
            mReactor = null;
            mStopLock.notify();
        }
        
        mDHT.close();
        Log.i("Telehash switch "+mLocalNode+" ending.");
    }
    
    @Override
    public void handleDatagram(Datagram datagram) {
        byte[] buffer = datagram.getBytes();
        Path source = datagram.getSource();
        Log.i("received datagram of "+buffer.length+" bytes from: "+source);

        // parse the packet
        Packet packet;
        try {
            packet = Packet.parse(mTelehash, buffer, source);
        } catch (RuntimeException e) {
            e.printStackTrace();
            return;            
        } catch (TelehashException e) {
            e.printStackTrace();
            return;
        }
        if (packet == null) {
            // null packet received; ignore
            return;
        }
        
        // process the packet
        handleIncomingPacket(packet);
    }
    
    private void handleIncomingPacket(Packet packet) {
        Log.i("incoming packet: "+packet);
        try {
            if (packet instanceof OpenPacket) {
                handleOpenPacket((OpenPacket)packet);
            } else if (packet instanceof LinePacket) {
                LinePacket linePacket = (LinePacket)packet;
                linePacket.getLine().handleIncoming(linePacket);
            }
        } catch (TelehashException e) {
            Log.i("error handling incoming packet: "+e);
            e.printStackTrace();
        }
    }
    
    private void calculateLineKeys(Line line, OpenPacket incomingOpen, OpenPacket outgoingOpen) {
        // calculate ECDH
        byte[] sharedSecret = mTelehash.getCrypto().calculateECDHSharedSecret(
                incomingOpen.getEllipticCurvePublicKey(),
                outgoingOpen.getEllipticCurvePrivateKey()
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
    
    private void handleOpenPacket(OpenPacket incomingOpenPacket) throws TelehashException {
        // is there a pending line for this?
        Node remoteNode = incomingOpenPacket.getSourceNode();
        Line line = mLineTracker.getByNode(remoteNode);
        if (line != null && (
                line.getOutgoingLineIdentifier() == null ||
                line.getOutgoingLineIdentifier().equals(incomingOpenPacket.getLineIdentifier())
        )) {
            // an existing line is present for this open.
            
            if (line.getState() != Line.State.PENDING) {
                // this line is already established -- this open packet
                // is redundant.
                return;
            }

            line.setRemoteOpenPacket(incomingOpenPacket);
            line.setOutgoingLineIdentifier(incomingOpenPacket.getLineIdentifier());
            calculateLineKeys(line, incomingOpenPacket, line.getLocalOpenPacket());
            line.setState(Line.State.ESTABLISHED);
            line.callOpenCompletionHandlers();            
            Log.i("new line established for local initiator");
        } else {
            // no pending line for this open -- enqueue a response open
            // packet to be sent and calculate ECDH
            // create an open packet
            OpenPacket replyOpenPacket = new OpenPacket(mTelehash.getIdentity(), incomingOpenPacket.getSourceNode());
            
            // perform the "pre-render" stage so values such as the EC key pair
            // have been generated.
            replyOpenPacket.preRender();
            
            // note: this reply open packet is *outgoing* but its embedded line identifier
            // is to be used for *incoming* line packets.
            line = new Line(mTelehash);
            line.setIncomingLineIdentifier(replyOpenPacket.getLineIdentifier());
            line.setLocalOpenPacket(replyOpenPacket);
            line.setRemoteOpenPacket(incomingOpenPacket);
            line.setOutgoingLineIdentifier(incomingOpenPacket.getLineIdentifier());
            line.setRemoteNode(incomingOpenPacket.getSourceNode());
            calculateLineKeys(line, incomingOpenPacket, replyOpenPacket);
            line.setState(Line.State.ESTABLISHED);
            
            // TODO: alert interested parties of the new line?
            Log.i("new line established for remote initiator");

            // alert the DHT of the new line
            // TODO: this should be abstracted into some sort of LineObserver
            mDHT.handleNewLine(line);
            
            // TODO: synchronize
            mLineTracker.add(line);
            
            // is there a pending reverse-open for this node?
            PendingReverseOpen pendingReverseOpen = mPendingReverseOpens.get(line.getRemoteNode());
            
            // enqueue the packet to be sent
            try {
                sendPacket(replyOpenPacket);
                if (pendingReverseOpen != null) {
                    pendingReverseOpen.completionHandler.completed(line, pendingReverseOpen.attachment);
                }
                // TODO: wait for response?
            } catch (RuntimeException e) {
                // rollback
                mLineTracker.remove(line);
                if (pendingReverseOpen != null) {
                    pendingReverseOpen.completionHandler.failed(e, pendingReverseOpen.attachment);
                }
                throw e;
            } catch (TelehashException e) {
                mLineTracker.remove(line);
                if (pendingReverseOpen != null) {
                    pendingReverseOpen.completionHandler.failed(e, pendingReverseOpen.attachment);
                }
                throw e;            
            }

        }
    }
        
    public Line getLineByNode(Node node) {
        return mLineTracker.getByNode(node);
    }

    public Line getLineByHashName(HashName hashName) {
        return mLineTracker.getByHashName(hashName);
    }

    private Map<String,ChannelHandler> mRegisteredChannelHandlers =
            new HashMap<String,ChannelHandler>();
    
    public void registerChannelHandler(String type, ChannelHandler channelHandler) {
        mRegisteredChannelHandlers.put(type, channelHandler);
    }
    
    public ChannelHandler getChannelHandler(String type) {
        return mRegisteredChannelHandlers.get(type);
    }
    
    public Scheduler getScheduler() {
        return mScheduler;
    }
    
    public Timeout getTimeout(OnTimeoutListener listener, long delay) {
        return new Timeout(mScheduler, listener, delay);
    }
}
