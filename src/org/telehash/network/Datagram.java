package org.telehash.network;

public class Datagram {
    private byte[] mBytes;
    private Path mSource;
    private Path mDestination;
    
    public Datagram(byte[] bytes, Path source, Path destination) {
        mBytes = bytes;
        mSource = source;
        mDestination = destination;
    }
    
    public byte[] getBytes() {
        return mBytes;
    }
    
    public Path getSource() {
        return mSource;
    }
    
    public Path getDestination() {
        return mDestination;
    }
}
