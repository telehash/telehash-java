package org.telehash.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class Line implements OnTimeoutListener {
    
    private static final int SHA256_DIGEST_SIZE = 32;
    private static final int LINE_OPEN_TIMEOUT = 5000;
    
    public enum State {
        INITIAL,
        NODE_LOOKUP,
        DIRECT_OPEN_PENDING,
        REVERSE_OPEN_PENDING,
        ESTABLISHED,
        TIMEOUT,
        ERROR
    };
    private State mState = State.INITIAL;
    
    private static class Completion<T> {
        public CompletionHandler<T> mHandler;
        public Object mAttachment;
        public Completion(CompletionHandler<T> handler, Object attachment) {
            this.mHandler = handler;
            this.mAttachment = attachment;
        }
    }
    private List<Completion<Line>> mOpenCompletionHandlers = new ArrayList<Completion<Line>>();

    private LineIdentifier mIncomingLineIdentifier;
    private LineIdentifier mOutgoingLineIdentifier;
    private Node mRemoteNode;
    private OpenPacket mLocalOpenPacket;
    private OpenPacket mRemoteOpenPacket;
    private byte[] mSharedSecret;
    private byte[] mEncryptionKey;
    private byte[] mDecryptionKey;
    
    private Timeout mTimeout;

    private Telehash mTelehash;
    private Map<ChannelIdentifier,Channel> mChannels = new HashMap<ChannelIdentifier,Channel>();
    private boolean mFinished = false;
    
    public Line(Telehash telehash) {
        mTelehash = telehash;
        mTimeout = telehash.getSwitch().getTimeout(this, 0);
    }
    
    public void setState(State state) {
        mState = state;
    }
    public State getState() {
        return mState;
    }
    
    public void setIncomingLineIdentifier(LineIdentifier lineIdentifier) {
        mIncomingLineIdentifier = lineIdentifier;
    }
    
    public LineIdentifier getIncomingLineIdentifier() {
        return mIncomingLineIdentifier;
    }

    public void setOutgoingLineIdentifier(LineIdentifier lineIdentifier) {
        mOutgoingLineIdentifier = lineIdentifier;
    }
    
    public LineIdentifier getOutgoingLineIdentifier() {
        return mOutgoingLineIdentifier;
    }

    public void setRemoteNode(Node remoteNode) {
        mRemoteNode = remoteNode;
    }
    
    public Node getRemoteNode() {
        return mRemoteNode;
    }
    
    public void setLocalOpenPacket(OpenPacket localOpenPacket) {
        mLocalOpenPacket = localOpenPacket;
    }
    
    public OpenPacket getLocalOpenPacket() {
        return mLocalOpenPacket;
    }
    
    public void setRemoteOpenPacket(OpenPacket remoteOpenPacket) {
        mRemoteOpenPacket = remoteOpenPacket;
    }
    
    public OpenPacket getRemoteOpenPacket() {
        return mRemoteOpenPacket;
    }
    
    public void setSharedSecret(byte[] sharedSecret) {
        if (sharedSecret == null || sharedSecret.length == 0) {
            throw new IllegalArgumentException("invalid shared secret");
        }
        mSharedSecret = sharedSecret;
    }
    
    public byte[] getSharedSecret() {
        return mSharedSecret;
    }

    public void setEncryptionKey(byte[] encryptionKey) {
        if (encryptionKey == null || encryptionKey.length != SHA256_DIGEST_SIZE) {
            throw new IllegalArgumentException("invalid encryption key");
        }
        mEncryptionKey = encryptionKey;
    }
    
    public byte[] getEncryptionKey() {
        return mEncryptionKey;
    }

    public void setDecryptionKey(byte[] decryptionKey) {
        if (decryptionKey == null || decryptionKey.length != SHA256_DIGEST_SIZE) {
            throw new IllegalArgumentException("invalid encryption key");
        }
        mDecryptionKey = decryptionKey;
    }
    
    public byte[] getDecryptionKey() {
        return mDecryptionKey;
    }
    
    public void addOpenCompletionHandler(
            CompletionHandler<Line> openCompletionHandler,
            Object openCompletionAttachment
    ) {
        if (mState == State.ESTABLISHED) {
            // line is already established, so complete immediately.
            openCompletionHandler.completed(this, openCompletionAttachment);
        } else {
            mOpenCompletionHandlers.add(new Completion<Line>(openCompletionHandler, openCompletionAttachment));
        }
    }
    
    /* intentionally package-private */
    void fail(Throwable e) {
        if (mFinished) {
            Log.e("line "+this+" fail after finish!");
            return;
        }
        mState = State.ERROR;
        mFinished = true;
        
        // cancel timeout
        mTimeout.cancel();
        
        // signal error
        for (Completion<Line> completion : mOpenCompletionHandlers) {
            if (completion.mHandler != null) {
                completion.mHandler.failed(e, completion.mAttachment);
            }
        }
    }
    
    public void completeOpen() {
        if (mFinished) {
            Log.e("line "+this+" complete after finish!");
            return;
        }
        mState = State.ESTABLISHED;
        mFinished = true;

        // cancel timeout
        mTimeout.cancel();
        
        // signal open completion
        for (Completion<Line> completion : mOpenCompletionHandlers) {
            if (completion.mHandler != null) {
                completion.mHandler.completed(this, completion.mAttachment);
            }
        }
    }
    
    public void startOpenTimer() {
        mTimeout.setDelay(LINE_OPEN_TIMEOUT);
    }
    
    public Telehash getTelehash() {
        return mTelehash;
    }
    
    public long getOpenTime() {
        if (mLocalOpenPacket != null) {
            return mLocalOpenPacket.getOpenTime();
        } else {
            return 0L;
        }
    }
    
    public Channel openChannel(String type, ChannelHandler channelHandler) {
        // create a channel object and establish a callback
        Channel channel = new Channel(mTelehash, this, type);

        // record channel handler
        channel.setChannelHandler(channelHandler);
        
        // track channel
        mChannels.put(channel.getChannelIdentifier(), channel);
        
        // consider the channel to be "open" even though we don't know
        // if the remote side will be happy with this channel type.
        if (channelHandler != null) {
            channelHandler.handleOpen(channel);
        }

        return channel;
    }
    
    public void handleIncoming(LinePacket linePacket) {
        ChannelPacket channelPacket = linePacket.getChannelPacket();
        Channel channel = mChannels.get(channelPacket.getChannelIdentifier());
        if (channel == null) {
            // is this the first communication of a new channel?
            // (it will have a type field)
            String type = channelPacket.getType();
            if (type == null) {
                Log.i("dropping packet for unknown channel without type");
                return;
            }
            
            // is anyone interested in channels of this type?
            ChannelHandler channelHandler = mTelehash.getSwitch().getChannelHandler(type);
            if (channelHandler == null) {
                Log.i("no channel handler for type; type=\""+channelPacket.getType()+
                        "\" cid="+channelPacket.getChannelIdentifier());
                return;
            }
            
            // create channel
            channel = new Channel(mTelehash, this, channelPacket.getChannelIdentifier(), type);
            channel.setChannelHandler(channelHandler);
            mChannels.put(channel.getChannelIdentifier(), channel);
            
            // invoke callback
            channelHandler.handleIncoming(channel, channelPacket);
            return;
        }
        // is this the end?
        if (channelPacket.isEnd()) {
            mChannels.remove(channel.getChannelIdentifier());
        }
        // dispatch to channel
        channel.receive(channelPacket);
    }
    
    public static Set<Line> sortByOpenTime(Collection<Line> lines) {
        TreeSet<Line> set = new TreeSet<Line>(new Comparator<Line>() {
            public int compare(Line a, Line b) {
                return (int)(a.getOpenTime() - b.getOpenTime());
            }
        });
        set.addAll(lines);
        return set;
    }
    
    public String toString() {
        return "Line["+mIncomingLineIdentifier+"->"+mOutgoingLineIdentifier+"@"+getOpenTime()+"]";
    }

    @Override
    public void handleTimeout() {
        TelehashException exception;
        switch (mState) {
        case NODE_LOOKUP:
            exception = new TelehashException("node lookup timeout");
            break;
        case DIRECT_OPEN_PENDING:
            exception = new TelehashException("line open timeout");
            break;
        default:
            exception = new TelehashException("unknown line timeout");
            break;
        }
        
        mState = State.TIMEOUT;

        // dereference from switch
        mTelehash.getSwitch().getLineManager().clearLine(this);

        // signal error
        for (Completion<Line> completion : mOpenCompletionHandlers) {
            completion.mHandler.failed(exception, completion.mAttachment);
        }
    }

}
