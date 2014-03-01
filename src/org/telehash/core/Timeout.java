package org.telehash.core;

import java.lang.ref.WeakReference;

public class Timeout implements Runnable {
    
    private Scheduler mScheduler;
    private WeakReference<OnTimeoutListener> mListener;
    private long mDelay;
    private Scheduler.Task mTask;

    public Timeout(Scheduler scheduler, OnTimeoutListener listener, long delay) {
        mScheduler = scheduler;
        mListener = new WeakReference<OnTimeoutListener>(listener);
        mDelay = 0;
        mTask = null;
        setDelay(delay);
    }
    
    public void setDelay(long delay) {
        if (delay > 0) {
            if (mTask != null) {
                mScheduler.updateTask(mTask, null, delay);
            } else {
                mTask = mScheduler.addTask(this, delay);
            }
        } else {
            if (mTask != null) {
                mScheduler.removeTask(mTask);
                mTask = null;
            }
        }
        mDelay = delay;
    }
    
    public long getDelay() {
        return mDelay;
    }
    
    /**
     * Reset (and re-start) the timer with the previously established delay.
     */
    public void reset() {
        if (mDelay > 0) {
            if (mTask != null) {
                mScheduler.updateTask(mTask, null, mDelay);
            } else {
                mTask = mScheduler.addTask(this, mDelay);
            }
        }
    }

    public void cancel() {
        if (mTask != null) {
            mScheduler.removeTask(mTask);
            mTask = null;
        }
    }

    @Override
    public void run() {
        OnTimeoutListener listener = mListener.get();
        if (listener != null) {
            listener.handleTimeout();
        } else {
            Log.e("timeout lost reference to listener");
        }
    }
}
