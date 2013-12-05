package org.telehash.core;

public class Line {
    
    private static final int LINE_IDENTIFIER_SIZE = 16;
    private static final int SHA256_DIGEST_SIZE = 32;
    
    public enum State {
        PENDING,
        ESTABLISHED,
        CLOSED
    };
    private State mState = State.CLOSED;

    private byte[] mIncomingLineIdentifier;
    private byte[] mOutgoingLineIdentifier;
    private Node mRemoteNode;
    private OpenPacket mLocalOpenPacket;
    private OpenPacket mRemoteOpenPacket;
    private byte[] mSharedSecret;
    private byte[] mEncryptionKey;
    private byte[] mDecryptionKey;
    private CompletionHandler<Line> mOpenCompletionHandler;
    private Object mOpenCompletionAttachment;

    public void setState(State state) {
        mState = state;
    }
    public State getState() {
        return mState;
    }
    
    public void setIncomingLineIdentifier(byte[] lineIdentifier) {
        if (lineIdentifier == null || lineIdentifier.length != LINE_IDENTIFIER_SIZE) {
            throw new IllegalArgumentException("invalid line id");
        }
        mIncomingLineIdentifier = lineIdentifier;
    }
    
    public byte[] getIncomingLineIdentifier() {
        return mIncomingLineIdentifier;
    }

    public void setOutgoingLineIdentifier(byte[] lineIdentifier) {
        if (lineIdentifier == null || lineIdentifier.length != LINE_IDENTIFIER_SIZE) {
            throw new IllegalArgumentException("invalid line id");
        }
        mOutgoingLineIdentifier = lineIdentifier;
    }
    
    public byte[] getOutgoingLineIdentifier() {
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
}
