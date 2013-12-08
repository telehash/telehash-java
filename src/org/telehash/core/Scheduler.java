package org.telehash.core;

import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

public class Scheduler {
    
    private static final int NANOSECONDS_IN_MILLISECOND = 1000000;
    
    public static class Task implements Comparable<Task> {
        public Runnable mRunnable;
        public long mTime;
        
        public Task(Runnable runnable, long time) {
            mRunnable = runnable;
            mTime = time;
        }
        
        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((mRunnable == null) ? 0 : mRunnable.hashCode());
            result = prime * result + (int) (mTime ^ (mTime >>> 32));
            return result;
        }
        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            Task other = (Task) obj;
            if (mRunnable == null) {
                if (other.mRunnable != null)
                    return false;
            } else if (!mRunnable.equals(other.mRunnable))
                return false;
            if (mTime != other.mTime)
                return false;
            return true;
        }
        
        @Override
        public int compareTo(Task other) {
            if (mTime < other.mTime) {
                return -1;
            } else if (mTime > other.mTime) {
                return +1;
            } else if (mRunnable.hashCode() < other.mRunnable.hashCode()) {
                return -1;
            } else if (mRunnable.hashCode() > other.mRunnable.hashCode()) {
                return +1;
            } else {
                return 0;
            }
        }
    }
    private SortedSet<Task> mTasks = new TreeSet<Task>();

    /**
     * Schedule a new task to be executed after a delay.
     * @param runnable
     * @param delay The delay in milliseconds.
     */
    public void addTask(Runnable runnable, long delay) {
        new Task(runnable, System.nanoTime() + delay*NANOSECONDS_IN_MILLISECOND);
    }

    /**
     * Run all tasks that are ready for execution.
     */
    public void runTasks() {
        long time = System.nanoTime();
        Iterator<Task> iterator = mTasks.iterator();
        while (iterator.hasNext()) {
            Task task = iterator.next();
            if (task.mTime > time) {
                break;
            }
            task.mRunnable.run();
            iterator.remove();
        }
    }
    
    /**
     * Return the number of milliseconds to the next scheduled task,
     * 0 if no upcoming tasks are scheduled, or -1 if tasks are ready
     * for immediate execution.
     * 
     * @return
     */
    public long getNextTaskTime() {
        if (mTasks.isEmpty()) {
            return 0;
        }
        long nextTaskTime = (mTasks.first().mTime - System.nanoTime())/NANOSECONDS_IN_MILLISECOND;
        if (nextTaskTime <= 0) {
            return -1;
        } else {
            return nextTaskTime;
        }
    }
}