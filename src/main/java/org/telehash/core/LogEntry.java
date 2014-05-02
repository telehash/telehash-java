package org.telehash.core;

import org.telehash.core.Log.Category;
import org.telehash.core.Log.Level;

public class LogEntry {

    private static long sStartTime = System.nanoTime();

    private Telehash mTelehash;
    private Category mCategory;
    private Level mLevel;
    private String mMessage;
    private Throwable mError;
    private long mTime;

    public LogEntry(Category category, Level level, String message) {
        mTelehash = Telehash.get();
        mCategory = category;
        mLevel = level;
        mMessage = message;
        mTime = System.nanoTime() - sStartTime;
    }

    public LogEntry(Category category, Level level, String message, Throwable error) {
        mTelehash = Telehash.get();
        mCategory = category;
        mLevel = level;
        mMessage = message;
        mError = error;
        mTime = System.nanoTime() - sStartTime;
    }

    public Telehash getTelehash() {
        return mTelehash;
    }

    public Category getCategory() {
        return mCategory;
    }

    public Level getLevel() {
        return mLevel;
    }

    public String getMessage() {
        return mMessage;
    }

    public Throwable getError() {
        return mError;
    }

    public long getTime() {
        return mTime;
    }
}
