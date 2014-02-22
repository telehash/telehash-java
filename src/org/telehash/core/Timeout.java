package org.telehash.core;

public class Timeout implements Runnable {
    
    private Scheduler mScheduler;
    private OnTimeoutListener mListener;
    private long mDelay;
    private Scheduler.Task mTask;

    public Timeout(Scheduler scheduler, OnTimeoutListener listener, long delay) {
        mScheduler = scheduler;
        mListener = listener;
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
    
    public void update() {
        if (mDelay > 0) {
            if (mTask != null) {
                mScheduler.updateTask(mTask, null, mDelay);
            } else {
                mTask = mScheduler.addTask(this, mDelay);
            }
        }
    }
    
    public void cancel() {
        mTask = null;
    }

    @Override
    public void run() {
        mListener.handleTimeout();
    }
}
