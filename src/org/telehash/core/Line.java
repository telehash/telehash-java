package org.telehash.core;

import org.telehash.crypto.CipherSet;

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
    private static final int LINE_OPEN_TIMEOUT = 15000;
    private static final int LINE_RECEIVE_TIMEOUT = 60000;
    private static final long FIRST_ODD_CHANNEL_ID = 1;
    private static final long FIRST_EVEN_CHANNEL_ID = 2;

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

    private CipherSet mCipherSet;
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
    private long mNextChannelId;

    public Line(Telehash telehash, Node remoteNode) {
        mTelehash = telehash;
        mTimeout = telehash.getSwitch().getTimeout(this, 0);
        mRemoteNode = remoteNode;

        if (remoteNode.getHashName().compareTo(telehash.getLocalNode().getHashName()) > 0) {
            // use even-numbered channels
            mNextChannelId = FIRST_EVEN_CHANNEL_ID;
        } else {
            // use odd-numbered channels
            mNextChannelId = FIRST_ODD_CHANNEL_ID;
        }
    }

    public void setState(State state) {
        mState = state;
    }
    public State getState() {
        return mState;
    }

    public void setCipherSetIdentifier(CipherSetIdentifier cipherSetIdentifier) {
        mCipherSet = mTelehash.getCrypto().getCipherSet(cipherSetIdentifier);
        if (mCipherSet == null) {
            throw new IllegalArgumentException("line requested with invalid cipherset id");
        }
    }

    public CipherSet getCipherSet() {
        return mCipherSet;
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
        if (! remoteNode.equals(mRemoteNode)) {
            throw new IllegalArgumentException(
                    "attempt to replace line node with non-equivalent node.");
        }
        mRemoteNode = remoteNode;
    }

    public Node getRemoteNode() {
        return mRemoteNode;
    }

    public PeerNode getRemotePeerNode() {
        if (mRemoteNode instanceof PeerNode) {
            return (PeerNode)mRemoteNode;
        } else {
            Log.e("peer node expected, but line still has: "+mRemoteNode);
            return null;
        }
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

    public ChannelIdentifier getNextChannelId() {
        long next = mNextChannelId;
        mNextChannelId += 2;
        return new ChannelIdentifier(mNextChannelId);
    }

    public void addOpenCompletionHandler(
            CompletionHandler<Line> openCompletionHandler,
            Object openCompletionAttachment
    ) {
        if (openCompletionHandler == null) {
            return;
        }
        if (mState == State.ESTABLISHED) {
            // line is already established, so complete immediately.
            openCompletionHandler.completed(this, openCompletionAttachment);
        } else {
            mOpenCompletionHandlers.add(
                    new Completion<Line>(openCompletionHandler, openCompletionAttachment)
            );
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
        Log.i(toString()+" open completed.");
        if (mFinished) {
            Log.e("line "+this+" complete after finish!");
            return;
        }
        mState = State.ESTABLISHED;
        mFinished = true;

        // reset the timeout (it will now be a line receive timeout.)
        mTimeout.setDelay(LINE_RECEIVE_TIMEOUT);

        // signal open completion
        Log.i(toString()+" calling open completion handlers: "+mOpenCompletionHandlers);
        for (Completion<Line> completion : mOpenCompletionHandlers) {
            if (completion.mHandler != null) {
                completion.mHandler.completed(this, completion.mAttachment);
            }
        }
    }

    public void startOpenTimer() {
        mTimeout.setDelay(LINE_OPEN_TIMEOUT);
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
        // reset the line timeout
        mTimeout.reset();
        Log.i(toString()+" TO-RESET to "+mTimeout.getDelay());

        ChannelPacket channelPacket = linePacket.getChannelPacket();
        Log.i("incoming: "+this+" "+channelPacket);
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
        // dispatch to channel
        channel.receive(channelPacket);
        // is this the end?
        if (channelPacket.isEnd()) {
            mChannels.remove(channel.getChannelIdentifier());
        }
    }

    public static Set<Line> sortByOpenTime(Collection<Line> lines) {
        TreeSet<Line> set = new TreeSet<Line>(new Comparator<Line>() {
            @Override
            public int compare(Line a, Line b) {
                return (int)(a.getOpenTime() - b.getOpenTime());
            }
        });
        set.addAll(lines);
        return set;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Line["+mRemoteNode.getHashName().getShortHash()+"#");
        if (mIncomingLineIdentifier != null) {
            sb.append(mIncomingLineIdentifier.asHex().substring(0, 8));
        }
        sb.append("-");
        if (mOutgoingLineIdentifier != null) {
            sb.append(mOutgoingLineIdentifier.asHex().substring(0, 8));
        }
        sb.append("]");
        return sb.toString();
    }

    @Override
    public void handleTimeout() {
        Log.e(""+this+" TIMEOUT");
        TelehashException exception;
        switch (mState) {
        case NODE_LOOKUP:
            exception = new TelehashException("node lookup timeout");
            break;
        case DIRECT_OPEN_PENDING:
            exception = new TelehashException("line open timeout");
            break;
        case REVERSE_OPEN_PENDING:
            exception = new TelehashException("line reverse open timeout");
            break;
        case ESTABLISHED:
            exception = new TelehashException("line receive timeout");
            break;
        default:
            exception = new TelehashException("unknown line timeout; state="+mState);
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
