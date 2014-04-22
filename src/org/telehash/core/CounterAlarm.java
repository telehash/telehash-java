package org.telehash.core;

/**
 * Execute a runnable when a signal count reaches a specified limit.
 */
public class CounterAlarm {

    private Runnable mRunnable;
    private int mCount = 0;
    private int mLimit = 0;

    public CounterAlarm(Runnable runnable) {
        mRunnable = runnable;
    }

    public void signal() {
        mCount++;
        if (mCount == mLimit) {
            if (mRunnable != null) {
                mRunnable.run();
            }
        }
    }

    public void setLimit(int limit) {
        mLimit = limit;
        if (mCount == limit) {
            if (mRunnable != null) {
                mRunnable.run();
            }
        }
    }
}
