package org.telehash.test.network;

import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;

import org.telehash.network.Datagram;
import org.telehash.network.DatagramHandler;
import org.telehash.network.InetPath;
import org.telehash.network.Reactor;

public class FakeReactorImpl implements Reactor {
    
    private FakeNetworkImpl mNetwork;
    private InetPath mPath;

    private int mPort;
    private DatagramHandler mDatagramHandler;
    private Queue<Datagram> mWriteQueue = new LinkedList<Datagram>();
    private Queue<Datagram> mReadQueue = new LinkedList<Datagram>();
    private Object mLock = new Object();
    
    /**
     * Construct a new ReactorImpl.
     * 
     * This constructor is intentionally package-private.
     */
    FakeReactorImpl(FakeNetworkImpl network, int port) {
        mNetwork = network;
        mPort = port;
        mPath = new InetPath(network.getPath().getAddress(), mPort);
    }

    void handleDatagram(Datagram datagram) {
        mReadQueue.offer(datagram);
        wakeup();
    }
    
    @Override
    public void setDatagramHandler(DatagramHandler datagramHandler) {
        mDatagramHandler = datagramHandler;
    }

    @Override
    public void start() throws IOException {
    }

    @Override
    public void stop() {
        wakeup();
    }
    
    @Override
    public void close() throws IOException {
    }

    @Override
    public void wakeup() {
        synchronized (mLock) {
            mLock.notifyAll();
        }
    }

    @Override
    public void select(long timeout) throws IOException {
        Datagram writeDatagram;
        Datagram readDatagram;

        synchronized (mLock) {
            // select
            if (mWriteQueue.isEmpty() && mReadQueue.isEmpty()) {
                try {
                    mLock.wait(timeout);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            
            writeDatagram = mWriteQueue.poll();
            readDatagram = mReadQueue.poll();
        }
        
        // dispatch
        if (writeDatagram != null) {
            mNetwork.getRouter().sendDatagram(writeDatagram);
        }
        if (readDatagram != null) {
            if (mDatagramHandler != null) {
                mDatagramHandler.handleDatagram(readDatagram);
            }
        }
    }
    
    /**
     * Send a datagram.  This is potentially called from an outside thread.
     * 
     * @param datagram
     */
    @Override
    public void sendDatagram(Datagram datagram) {
        synchronized (mLock) {
            datagram.setSource(mPath);
            mWriteQueue.offer(datagram);
            wakeup();
        }
    }
}
