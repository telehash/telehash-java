package org.telehash.core;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

import org.telehash.network.impl.InetEndpoint;

/**
 * The Switch class is the heart of Telehash. The switch is responsible for
 * managing identity and node information, maintaining the DHT, and facilitating
 * inter-node communication.
 */
public class Switch {
    
    private static final int DEFAULT_PORT = 42424;

    private Identity mIdentity;
    private Set<Node> mSeeds;
    private int mPort;
    
    private Selector mSelector;
    private SelectionKey mSelectionKey;
    private DatagramChannel mChannel;
    private boolean mStopRequested = false;
    private Queue<Packet> mWriteQueue = new LinkedList<Packet>();

    public Switch(Identity identity, Set<Node> seeds) {
        mIdentity = identity;
        mSeeds = seeds;
        mPort = DEFAULT_PORT;
    }

    public Switch(Identity identity, Set<Node> seeds, int port) {
        mIdentity = identity;
        mSeeds = seeds;
        mPort = port;
    }

    public void start() throws TelehashException {
        
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
    
    public void sendPacket(Packet packet) {
        System.out.println("enqueuing packet");
        // TODO: synchronize writequeue
        // TODO: limit write queue (block if limit reached?)
        mWriteQueue.offer(packet);
        mSelector.wakeup();
    }

    private void loop() {
        System.out.println("switch loop with identity="+mIdentity+" and seeds="+mSeeds);
        
        try {
            while (true) {

                // prepare for select
                if (mWriteQueue.isEmpty()) {
                    mSelectionKey.interestOps(SelectionKey.OP_READ);
                } else {
                    mSelectionKey.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
                    System.out.println("selecting for write");
                }
                
                // select
                mSelector.select();
                
                // dispatch
                if (mSelector.selectedKeys().contains(mSelectionKey)) {
                    if (mSelectionKey.isReadable()) {
                        handleIncoming();
                    }
                    if (mSelectionKey.isWritable()) {
                        handleOutgoing();
                    }
                }
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
    }
    
    private void handleOutgoing() {
        Packet packet = mWriteQueue.poll();
        if (packet == null) {
            // the write queue is empty.
            return;
        }
        
        // for now, just send to the sole seed.
        // TODO: this will obviously require far more sophistication.
        Node seed = mSeeds.iterator().next();
        InetAddress seedAddress = ((InetEndpoint)seed.getEndpoint()).getAddress();
        int seedPort = ((InetEndpoint)seed.getEndpoint()).getPort();
        
        // TODO: don't allocate a new buffer every time.
        ByteBuffer buffer = ByteBuffer.allocate(2048);
        buffer.clear();
        buffer.putLong(42L);
        buffer.flip();
        try {
            mChannel.send(buffer, new InetSocketAddress(seedAddress, seedPort));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.out.println("datagram sent.");
    }
}
