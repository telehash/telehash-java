package org.telehash.core;

/**
 * This class is a utility for blocking execution until another thread signals
 * its readiness (or signals an error).
 */
public class Flag {
    private boolean flagged = false;
    private Throwable error = null;
    
    /**
     * Wait until another thread signals its readiness (or error).
     * @return An error, if the other thread indicated such.
     */
    public Throwable waitForSignal() {
        synchronized (this) {
            while (flagged == false) {
                try {
                    this.wait();
                } catch (InterruptedException e) {
                }
            }
        }
        return error;
    }
    
    /**
     * Signal readiness to the blocked thread.
     */
    public void signal() {
        synchronized (this) {
            flagged = true;
            this.notify();
        }            
    }
    
    /**
     * Reset to the original state.
     */
    public void reset() {            
        synchronized (this) {
            flagged = false;
            error = null;
        }
    }
    
    /**
     * Signal an error to the blocked thread.
     * @param e The error to signal.
     */
    public void signalError(Throwable e) {
        error = e;
        signal();
    }
}
