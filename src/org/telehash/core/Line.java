package org.telehash.core;

import java.util.HashMap;
import java.util.Map;

public class Line {
    
    private static final int SHA256_DIGEST_SIZE = 32;
    
    public enum State {
        PENDING,
        ESTABLISHED,
        CLOSED
    };
    private State mState = State.CLOSED;

    private LineIdentifier mIncomingLineIdentifier;
    private LineIdentifier mOutgoingLineIdentifier;
    private Node mRemoteNode;
    private OpenPacket mLocalOpenPacket;
    private OpenPacket mRemoteOpenPacket;
    private byte[] mSharedSecret;
    private byte[] mEncryptionKey;
    private byte[] mDecryptionKey;
    private CompletionHandler<Line> mOpenCompletionHandler;
    private Object mOpenCompletionAttachment;

    private Telehash mTelehash;
    private Map<ChannelIdentifier,Channel> mChannels = new HashMap<ChannelIdentifier,Channel>();
    
    public Line(Telehash telehash) {
        mTelehash = telehash;
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
    
    public void setOpenCompletionHandler(
            CompletionHandler<Line> openCompletionHandler,
            Object openCompletionAttachment
    ) {
        mOpenCompletionHandler = openCompletionHandler;
        mOpenCompletionAttachment = openCompletionAttachment;
    }
    
    public void callOpenCompletionHandler() {
        if (mOpenCompletionHandler != null) {
            mOpenCompletionHandler.completed(this, mOpenCompletionAttachment);
        }
    }
    
    public Channel openChannel(String type, ChannelHandler channelHandler) {
        // create a channel object and establish a callback
        Channel channel = new Channel(mTelehash, this, type);

        // record channel handler
        channel.setChannelHandler(channelHandler);
        
        // track channel
        mChannels.put(channel.getChannelIdentifier(), channel);
        
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
                System.out.println("dropping packet for unknown channel without type");
                return;
            }
            // is anyone interested in channels of this type?
            ChannelHandler channelHandler = mTelehash.getSwitch().getChannelHandler(type);
            if (channelHandler == null) {
                System.out.println("no channel handler for type");
                return;
            }
            
            // create channel
            channel = new Channel(mTelehash, this, type);
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
        // dispatch to channel handler
        channel.getChannelHandler().handleIncoming(channel, channelPacket);
    }
}
