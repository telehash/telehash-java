package org.telehash.core;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import org.telehash.dht.DHT;
import org.telehash.network.Endpoint;
import org.telehash.network.impl.InetEndpoint;

/**
 * The Switch class is the heart of Telehash. The switch is responsible for
 * managing identity and node information, maintaining the DHT, and facilitating
 * inter-node communication.
 */
public class Switch {
    
    private static final int DEFAULT_PORT = 42424;

    private Telehash mTelehash;
    private Set<Node> mSeeds;
    private int mPort;
    
    private Selector mSelector;
    private SelectionKey mSelectionKey;
    private DatagramChannel mChannel;
    private boolean mStopRequested = false;
    private Queue<Packet> mWriteQueue = new LinkedList<Packet>();
    
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
                    System.out.println("XXX has key, but value is null");
                } else {
                    System.out.println("XXX cannot find "+
                            lineIdentifier+" ; candidates include:");
                    for (LineIdentifier id : mIncomingLineIdentifierToLineMap.keySet()) {
                        System.out.println("XXX     "+id+" "+id.hashCode());
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
                sb.append(line.getState().name()+"\n");
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
        Endpoint localEndpoint = mTelehash.getNetwork().getPreferredLocalEndpoint();
        if (localEndpoint == null) {
            throw new TelehashException("no network");
        }
        mLocalNode = new Node(mTelehash.getIdentity().getPublicKey(), localEndpoint);
        
        // provision datagram channel and selector
        try {
            mSelector = Selector.open();
            mChannel = DatagramChannel.open();
            // TODO: configure port number
            mChannel.socket().bind(new InetSocketAddress(mPort));
            mChannel.configureBlocking(false);
            mSelectionKey = mChannel.register(mSelector, SelectionKey.OP_READ);
        } catch (IOException e) {
            try {
                mSelector.close();
                mChannel.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            throw new TelehashException(e);
        }
        
        // launch thread
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                // TODO: make Switch extend Thread, to save a stack frame here?
                loop();
            }
        });
        thread.start();
    }
    
    public void stop() {
        if (mSelector != null) {
            mStopRequested = true;
            mSelector.wakeup();
            // TODO: wait for loop to finish?
        }
    }
    
    public Line getLine(LineIdentifier lineIdentifier) {
        return mLineTracker.getByIncomingLineIdentifier(lineIdentifier);
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
        System.out.println("openPacket.lineid="+openPacket.getLineIdentifier());
        line.setIncomingLineIdentifier(openPacket.getLineIdentifier());
        line.setLocalOpenPacket(openPacket);
        line.setRemoteNode(destination);
        line.setState(Line.State.PENDING);
        line.setOpenCompletionHandler(handler, attachment);
        
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
        Channel channel = line.openChannel("peer", new ChannelHandler() {
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
        });
        
        Map<String,Object> fields = new HashMap<String,Object>();
        fields.put("peer", destination.getHashName().asHex());
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

        return;
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
        System.out.println("enqueuing packet");
        // TODO: synchronize writequeue
        // TODO: limit write queue (block if limit reached?)
        mWriteQueue.offer(packet);
        mSelector.wakeup();
    }

    private void loop() {
        System.out.println("switch loop with identity="+mTelehash.getIdentity()+" and seeds="+mSeeds);
        
        mDHT = new DHT(mTelehash, mLocalNode, mSeeds);
        mDHT.init();
        
        try {
            while (true) {

                // prepare for select
                if (mWriteQueue.isEmpty()) {
                    mSelectionKey.interestOps(SelectionKey.OP_READ);
                } else {
                    mSelectionKey.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
                    System.out.println("selecting for write");
                }
                
                long nextTaskTime = mScheduler.getNextTaskTime();
                if (nextTaskTime == -1) {
                    // hack: if any tasks are currently runnable, use a select timeout
                    // of 1ms and then run them.
                    nextTaskTime = 1;
                }
                
                // select
                mSelector.select(nextTaskTime);
                
                // dispatch
                if (mSelector.selectedKeys().contains(mSelectionKey)) {
                    if (mSelectionKey.isReadable()) {
                        handleIncoming();
                    }
                    if (mSelectionKey.isWritable()) {
                        handleOutgoing();
                    }
                }
                
                // run any timed tasks
                mScheduler.runTasks();
                
                if (mStopRequested) {
                    break;
                }
            }
        } catch (IOException e) {
            System.out.println("loop ending abnormaly");
            e.printStackTrace();
        } finally {
            try {
                mSelector.close();
                mChannel.close();
            } catch (IOException e) {
                System.out.println("error closing selector and/or channel.");
                e.printStackTrace();
            }
            mSelector = null;
        }
        
        System.out.println("loop ending");
    }
    
    private void handleIncoming() {
        // TODO: don't allocate a new buffer every time.
        ByteBuffer buffer = ByteBuffer.allocate(2048);
        SocketAddress socketAddress;
        try {
            socketAddress = mChannel.receive(buffer);
            if (socketAddress == null) {
                // no datagram available to read.
                return;
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        }
        System.out.println("received datagram of "+buffer.position()+" bytes from: "+socketAddress);

        // extract a byte array of the datagram buffer
        // TODO: retool parse() to take length/offset args to avoid excessive copying.
        byte[] packetBuffer = new byte[buffer.position()];
        System.arraycopy(buffer.array(), 0, packetBuffer, 0, buffer.position());

        // parse the packet
        Packet packet;
        try {
            packet = Packet.parse(
                    mTelehash,
                    packetBuffer,
                    mTelehash.getNetwork().socketAddressToEndpoint(socketAddress)
            );
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
        System.out.println("incoming packet: "+packet);
        try {
            if (packet instanceof OpenPacket) {
                handleOpenPacket((OpenPacket)packet);
            } else if (packet instanceof LinePacket) {
                LinePacket linePacket = (LinePacket)packet;
                linePacket.getLine().handleIncoming(linePacket);
            }
        } catch (TelehashException e) {
            System.out.println("error handling incoming packet: "+e);
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
        System.out.println("handleOpenPacket() top:\n"+mLineTracker);
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
            line.callOpenCompletionHandler();            
            System.out.println("new line established for local initiator");
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
            System.out.println("new line established for remote initiator");

            // alert the DHT of the new line
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
        System.out.println("handleOpenPacket() bottom:\n"+mLineTracker);
    }
    
    private void handleOutgoing() {
        Packet packet = mWriteQueue.poll();
        if (packet == null) {
            // the write queue is empty.
            return;
        }
        
        Node destination = packet.getDestinationNode();
        System.out.println("sending to hashname="+destination);
        InetAddress destinationAddress = ((InetEndpoint)destination.getEndpoint()).getAddress();
        int destinationPort = ((InetEndpoint)destination.getEndpoint()).getPort();
        
        // TODO: don't allocate a new buffer every time.
        ByteBuffer buffer = ByteBuffer.allocate(2048);
        buffer.clear();
        try {
            buffer.put(packet.render());
        } catch (TelehashException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        buffer.flip();
        try {
            mChannel.send(buffer, new InetSocketAddress(destinationAddress, destinationPort));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.out.println("datagram sent.");
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
}
