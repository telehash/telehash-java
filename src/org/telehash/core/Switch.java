package org.telehash.core;

import org.telehash.dht.DHT;
import org.telehash.network.Datagram;
import org.telehash.network.DatagramHandler;
import org.telehash.network.InetPath;
import org.telehash.network.Message;
import org.telehash.network.MessageHandler;
import org.telehash.network.Path;
import org.telehash.network.Reactor;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * The Switch class is the heart of Telehash. The switch is responsible for
 * managing identity and node information, maintaining the DHT, and facilitating
 * inter-node communication.
 */
public class Switch implements DatagramHandler, MessageHandler {

    private static final int DEFAULT_PORT = 42424;

    private Telehash mTelehash;
    private Set<Node> mSeeds;
    private int mPort;
    private Reactor mReactor;
    private Thread mThread;

    private Flag mStartFlag = new Flag();
    private Flag mStopFlag = new Flag();
    private boolean mStopRequested = false;

    private Node mLocalNode;
    private Scheduler mScheduler = new Scheduler();

    private DHT mDHT;
    private LineManager mLineManager;

    private static class OpenChannelMessage extends Message {
        final Node destination;
        final String type;
        final ChannelHandler channelHandler;
        public OpenChannelMessage(Node destination, String type, ChannelHandler channelHandler) {
            this.destination = destination;
            this.type = type;
            this.channelHandler = channelHandler;
        }
    }

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

        mLocalNode = new Node(mTelehash.getIdentity().getHashNamePublicKeys(), inetPath);

        // provision the reactor
        mReactor = mTelehash.getNetwork().createReactor(mPort);
        mReactor.setDatagramHandler(this);
        mReactor.setMessageHandler(this);
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
        mStartFlag.waitForSignal();
        mStartFlag.reset();
    }

    public void stop() {
        synchronized (this) {
            if (mReactor != null) {
                mStopRequested = true;
                mReactor.stop();

                if (! Thread.currentThread().equals(mThread)) {
                    mStopFlag.waitForSignal();
                }
            }
        }

        mStopFlag.reset();
    }

    public DHT getDHT() {
        return mDHT;
    }

    public LineManager getLineManager() {
        return mLineManager;
    }

    public void openChannel(
            Node destination,
            final String type,
            final ChannelHandler channelHandler
    ) {
        Message message = new OpenChannelMessage(destination, type, channelHandler);
        mReactor.sendMessage(message);
    }

    public void openChannelNow(
            Node destination,
            final String type,
            final ChannelHandler channelHandler
    ) {
        if (mLocalNode.equals(destination)) {
            channelHandler.handleError(null,
                    new TelehashException("attempt to open a channel to myself")
            );
            return;
        }
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
        try {
            mLineManager.openLine(destination, false, lineOpenCompletionHandler, null);
        } catch (IllegalArgumentException e) {
            channelHandler.handleError(null, e);
        }
    }

    public void sendPacket(Packet packet) throws TelehashException {
        if (packet == null) {
            return;
        }
        Node destination = packet.getDestinationNode();
        Log.i("outgoing packet: "+packet);

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
        mStartFlag.signal();

        try {
            while (true) {
                long nextTaskTime;
                nextTaskTime = mScheduler.getNextTaskTime();
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
                    Log.i("switch stop requested");
                    break;
                }
            }
        } catch (IOException e) {
            Log.i("switch loop ending abnormaly");
            e.printStackTrace();
        } finally {
            try {
                mReactor.close();
            } catch (IOException e) {
                Log.i("error closing reactor.");
                e.printStackTrace();
            }
        }

        mDHT.close();
        Log.i("Telehash switch "+mLocalNode+" ending.");

        // signal loop completion
        mStopFlag.signal();
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

    @Override
    public void handleMessage(Message message) {
        // process any pending messages
        if (message != null) {
            if (message instanceof OpenChannelMessage) {
                OpenChannelMessage m = (OpenChannelMessage)message;
                openChannelNow(m.destination, m.type, m.channelHandler);
            }
        }
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
