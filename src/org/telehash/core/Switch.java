package org.telehash.core;

import java.io.IOException;
import java.util.HashMap;
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
    private Scheduler mScheduler = new Scheduler();
    
    private DHT mDHT;
    private LineManager mLineManager;

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
    
    private Object mStartLock = new Object();
    private boolean mStartLockState = false;

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
        
        // block until the start tasks in loop() have finished.
        synchronized (mStartLock) {
            while (mStartLockState == false) {
                try {
                    mStartLock.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
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
    
    public DHT getDHT() {
        return mDHT;
    }
    
    public LineManager getLineManager() {
        return mLineManager;
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
        
        // open a new line (or re-use an existing line)
        mLineManager.openLine(destination, false, lineOpenCompletionHandler, null);
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
        
        mLineManager = new LineManager(mTelehash);
        mLineManager.init();

        mDHT = new DHT(mTelehash, mLocalNode, mSeeds);
        mDHT.init();
        
        // signal start completion
        synchronized (mStartLock) {
            mStartLockState = true;
            mStartLock.notify();
        }

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
                mLineManager.handleOpenPacket((OpenPacket)packet);
            } else if (packet instanceof LinePacket) {
                LinePacket linePacket = (LinePacket)packet;
                linePacket.getLine().handleIncoming(linePacket);
            }
        } catch (TelehashException e) {
            Log.i("error handling incoming packet: "+e);
            e.printStackTrace();
        }
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
