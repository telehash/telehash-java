package org.telehash.network.impl;

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

import org.telehash.core.Log;
import org.telehash.network.Datagram;
import org.telehash.network.DatagramHandler;
import org.telehash.network.InetPath;
import org.telehash.network.Message;
import org.telehash.network.MessageHandler;
import org.telehash.network.Path;
import org.telehash.network.Reactor;

public class ReactorImpl implements Reactor {

    private int mPort;
    private Selector mSelector;
    private SelectionKey mSelectionKey;
    private DatagramChannel mChannel;
    private DatagramHandler mDatagramHandler;
    private MessageHandler mMessageHandler;
    private Queue<Datagram> mWriteQueue = new LinkedList<Datagram>();
    private Queue<Message> mMessageQueue = new LinkedList<Message>();
    
    /**
     * Construct a new ReactorImpl.
     * 
     * This constructor is intentionally package-private.
     */
    ReactorImpl(int port) {
        mPort = port;
    }

    @Override
    public void setDatagramHandler(DatagramHandler datagramHandler) {
        mDatagramHandler = datagramHandler;
    }

    @Override
    public void setMessageHandler(MessageHandler messageHandler) {
        mMessageHandler = messageHandler;
    }
    
    @Override
    public void start() throws IOException {
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
            throw e;
        }        
    }

    @Override
    public void stop() {
        if (mSelector != null) {
            mSelector.wakeup();
        }
    }
    
    @Override
    public void close() throws IOException {
        mSelector.close();
        mChannel.close();
        mSelector = null;
    }

    @Override
    public void wakeup() {
        if (mSelector != null) {
            mSelector.wakeup();
        }
    }

    @Override
    public void select(long timeout) throws IOException {
        // prepare for select
        if (mWriteQueue.isEmpty()) {
            mSelectionKey.interestOps(SelectionKey.OP_READ);
        } else {
            mSelectionKey.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
            Log.i("selecting for write");
        }

        // select
        mSelector.select(timeout);        	
        
        // dispatch
        if (mSelector.selectedKeys().contains(mSelectionKey)) {
            if (mSelectionKey.isReadable()) {
                handleIncoming();
            }
            if (mSelectionKey.isWritable()) {
                handleOutgoing();
            }
        }
        synchronized (mMessageQueue) {
	        Message message = mMessageQueue.poll();
	        if (message != null && mMessageHandler != null) {
	        	mMessageHandler.handleMessage(message);
	        }
        }
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
        Path sourcePath = Path.socketAddressToPath(socketAddress);
        if (sourcePath == null) {
            return;
        }

        // extract a byte array of the datagram buffer
        // TODO: retool parse() to take length/offset args to avoid excessive copying.
        byte[] packetBuffer = new byte[buffer.position()];
        System.arraycopy(buffer.array(), 0, packetBuffer, 0, buffer.position());

        if (mDatagramHandler != null) {
            mDatagramHandler.handleDatagram(new Datagram(packetBuffer,sourcePath,null));
        }
    }

    private void handleOutgoing() {
        Datagram datagram = mWriteQueue.poll();
        if (datagram == null) {
            // the write queue is empty.
            return;
        }

        Path destination = datagram.getDestination();
        if (! (destination instanceof InetPath)) {
            return;
        }
        InetAddress destinationAddress = ((InetPath)destination).getAddress();
        int destinationPort = ((InetPath)destination).getPort();
        
        // TODO: don't allocate a new buffer every time.
        ByteBuffer buffer = ByteBuffer.allocate(2048);
        buffer.clear();
        buffer.put(datagram.getBytes());
        buffer.flip();
        try {
            mChannel.send(buffer, new InetSocketAddress(destinationAddress, destinationPort));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Log.i("datagram sent.");
    }
    
    /**
     * Send a datagram.  This is potentially called from an outside thread.
     * 
     * @param datagram
     */
    @Override
    public void sendDatagram(Datagram datagram) {
        // TODO: synchronize writequeue
        // TODO: limit write queue (block if limit reached?)
        mWriteQueue.offer(datagram);
        mSelector.wakeup();
    }
    
    @Override
    public void sendMessage(Message message) {
    	synchronized (mMessageQueue) {
    		mMessageQueue.offer(message);
            mSelector.wakeup();
    	}
    }
    
}
