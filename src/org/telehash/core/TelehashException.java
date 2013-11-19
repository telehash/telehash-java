package org.telehash.core;

/**
 * This is the base class for all Telehash exceptions. This class may be
 * instantiated directly to indicate an error condition, or extended to create a
 * specialized exception.
 */
@SuppressWarnings("serial")
public class TelehashException extends Exception {
    public TelehashException(String message) {
        super(message);
    }
    public TelehashException(Throwable e) {
        super(e);
    }
    public TelehashException(String message, Throwable e) {
        super(message, e);
    }
}
