package org.telehash.core;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

public class Scheduler {

    private static final int NANOSECONDS_IN_MILLISECOND = 1000000;

    public static class Task implements Comparable<Task> {
        private Runnable mRunnable;
        private long mTime;

        public Task(Runnable runnable, long time) {
            mRunnable = runnable;
            mTime = time;
        }

        @Override
        public String toString() {
            return "Task["+mRunnable.hashCode()+"/"+mTime+"]";
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
    public Task addTask(Runnable runnable, long delay) {
        Task task = new Task(runnable, System.nanoTime() + delay*NANOSECONDS_IN_MILLISECOND);
        mTasks.add(task);
        return task;
    }

    /**
     * Remove the specified task from the scheduler.
     *
     * @param task
     */
    public void removeTask(Task task) {
        mTasks.remove(task);
    }

    /**
     * Updated an existing task to use a new delay and/or runnable.
     *
     * @param runnable
     *            The runnable to run at the specified time, or null if the
     *            runnable should not be updated.
     * @param delay
     *            The delay in milliseconds, or -1 if the delay should not be
     *            updated.
     */
    public void updateTask(Task task, Runnable runnable, long delay) {
        mTasks.remove(task);
        if (runnable != null) {
            task.mRunnable = runnable;
        }
        if (delay != -1) {
            task.mTime = System.nanoTime() + delay*NANOSECONDS_IN_MILLISECOND;
        }
        mTasks.add(task);
    }

    /**
     * Run all tasks that are ready for execution.
     */
    public void runTasks() {
        long time = System.nanoTime();

        // iterate over a copy of the task list, since otherwise
        // the called runnable may add a task and cause us to
        // receive a ConcurrentModificationException.
        //
        // TODO: adding all the tasks into a separate sorted tree is a lot
        // of work to do for every iteration of the switch's select loop.
        // find a better way.
        Set<Task> tasks = new TreeSet<Task>(mTasks);

        Iterator<Task> iterator = tasks.iterator();
        Set<Task> removalSet = new HashSet<Task>();
        while (iterator.hasNext()) {
            Task task = iterator.next();
            if (task.mTime > time) {
                break;
            }
            task.mRunnable.run();
            removalSet.add(task);
        }
        mTasks.removeAll(removalSet);
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

    public void dump() {
        Log.i("SCHEDULER TASKS:");
        for (Task task : mTasks) {
            Log.i("    "+task);
        }
    }
}
