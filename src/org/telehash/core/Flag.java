package org.telehash.core;

/**
 * This class is a utility for blocking execution until another thread signals
 * its readiness (or signals an error).
 */
public class Flag {
    private static final int NANOSECONDS_IN_MILLISECOND = 1000000;
    private boolean mFlagged = false;
    private boolean mTimeoutOccurred = false;
    private Throwable mError = null;
    
    /**
     * Wait until another thread signals its readiness (or error).
     * @return An error, if the other thread indicated such.
     */
    public Throwable waitForSignal() {
        synchronized (this) {
            while (mFlagged == false) {
                try {
                    this.wait();
                } catch (InterruptedException e) {
                }
            }
        }
        return mError;
    }

    /**
     * Wait until another thread signals its readiness (or error), or until the
     * specified time elapses.
     * 
     * @return An error, if the other thread indicated such.
     */
    public Throwable waitForSignal(int timeout) {
        long now = System.nanoTime();
        long stopTime = now + (long)timeout*NANOSECONDS_IN_MILLISECOND;
        synchronized (this) {
            while (mFlagged == false && now <= stopTime) {
                int remainingTime = (int)((stopTime-now)/NANOSECONDS_IN_MILLISECOND);
                try {
                    this.wait(remainingTime);
                } catch (InterruptedException e) {
                }
                now = System.nanoTime();
            }
            if (mFlagged == false) {
                mTimeoutOccurred = true;
            }
        }
        return mError;
    }

    /**
     * Signal readiness to the blocked thread.
     */
    public void signal() {
        synchronized (this) {
            mFlagged = true;
            this.notify();
        }            
    }
    
    /**
     * Reset to the original state.
     */
    public void reset() {            
        synchronized (this) {
            mFlagged = false;
            mError = null;
            mTimeoutOccurred = false;
        }
    }
    
    /**
     * Signal an error to the blocked thread.
     * @param e The error to signal.
     */
    public void signalError(Throwable e) {
        mError = e;
        signal();
    }
    
    /**
     * After waitForSignal(int) returns, this method will return true if the
     * wait timed out.
     * 
     * @return
     */
    public boolean timeoutOccurred() {
        return mTimeoutOccurred;
    }
}
