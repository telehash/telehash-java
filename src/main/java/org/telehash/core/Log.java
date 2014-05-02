package org.telehash.core;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class Log {

    public enum Category {
        UNKNOWN
    };

    public enum Level {
        DEBUG,
        VERBOSE,
        INFO,
        WARNING,
        ERROR
    };

    private static Object sLock = new Object();
    private static List<LogListener> sLogListeners = new ArrayList<LogListener>();
    private static boolean mInitialized = false;

    private static ThreadLocal<LinkedList<LogEntry>> sBuffer =
            new ThreadLocal<LinkedList<LogEntry>>();

    public static void d(String msg, Object... args) {
        println(Level.DEBUG, msg, args);
    }
    public static void v(String msg, Object... args) {
        println(Level.VERBOSE, msg, args);
    }
    public static void i(String msg, Object... args) {
        println(Level.INFO, msg, args);
    }
    public static void w(String msg, Object... args) {
        println(Level.WARNING, msg, args);
    }
    public static void e(String msg, Object... args) {
        println(Level.ERROR, msg, args);
    }

    public static void setLogListener(LogListener logListener) {
        sLogListeners.clear();
        sLogListeners.add(logListener);
    }

    public static void addLogListener(LogListener logListener) {
        sLogListeners.add(logListener);
    }

    private static void println(Level level, String msg, Object... args) {
        // first-call initialization
        if (mInitialized == false) {
            if (sLogListeners.isEmpty()) {
                sLogListeners.add(new StandardLogger());
            }
            mInitialized = true;
        }

        if (msg == null || msg.isEmpty()) {
            return;
        }
        String text = String.format(msg, args);
        LogEntry entry;
        entry = new LogEntry(Category.UNKNOWN, level, text);
        if (args.length > 0 && (args[args.length-1] instanceof Throwable)) {
            Throwable throwable = (Throwable)args[args.length - 1];
            entry = new LogEntry(Category.UNKNOWN, level, text, throwable);
        } else {
            entry = new LogEntry(Category.UNKNOWN, level, text);
        }

        synchronized (sLock) {
            LinkedList<LogEntry> buffer = sBuffer.get();
            if (buffer != null) {
                buffer.add(entry);
            } else {
                for (LogListener listener : sLogListeners) {
                    listener.onLogEvent(entry);
                }
            }
        }
    }

    public static void buffer() {
        synchronized (sLock) {
            LinkedList<LogEntry> buffer = sBuffer.get();
            if (buffer != null) {
                throw new IllegalStateException("buffer() called twice without flush().");
            }
            sBuffer.set(new LinkedList<LogEntry>());
        }
    }

    public static void flush() {
        synchronized (sLock) {
            LinkedList<LogEntry> buffer = sBuffer.get();
            if (buffer == null) {
                throw new IllegalStateException("flush() called without buffer().");
            }
            for (LogEntry entry : buffer) {
                for (LogListener listener : sLogListeners) {
                    listener.onLogEvent(entry);
                }
            }
            sBuffer.remove();
        }
    }
}
