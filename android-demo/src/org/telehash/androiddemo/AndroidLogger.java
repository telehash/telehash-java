package org.telehash.androiddemo;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;

import org.telehash.core.LogEntry;
import org.telehash.core.LogListener;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedList;

public class AndroidLogger implements LogListener {

    private static final int MAX_ENTRIES = 1000;

    private LinkedList<LogEntry> mRingBuffer = new LinkedList<LogEntry>();

    @Override
    public void onLogEvent(LogEntry entry) {
        synchronized (this) {
            mRingBuffer.add(entry);
            if (mRingBuffer.size() > MAX_ENTRIES) {
                mRingBuffer.removeFirst();
            }
            showLogEntry(entry);
        }
    }

    public static String renderEntry(LogEntry entry) {
        StringBuilder output = new StringBuilder();
        renderEntry(entry, output);
        return output.toString();
    }

    public static void renderEntry(LogEntry entry, StringBuilder output) {
        String text = entry.getMessage();
        for (String line : text.split("\n")) {
            if (! line.isEmpty()) {
                output.append(line+"\n");
            }
        }

        Throwable error = entry.getError();
        if (error != null) {
            StringWriter errors = new StringWriter();
            error.printStackTrace(new PrintWriter(errors));
            for (String line : errors.toString().split("\n")) {
                line.trim();
                output.append(line+"\n");
            }
        }
    }

    public String render() {
        StringBuilder output = new StringBuilder();

        synchronized (this) {
            for (LogEntry entry : mRingBuffer) {
                renderEntry(entry, output);
            }
        }

        return output.toString();
    }

    private LogFragment mLogFragment = null;
    public void setLogFragment(LogFragment logFragment) {
        mLogFragment = logFragment;
    }

    private Handler mHandler = null;
    public void showLogEntry(LogEntry entry) {
        if (mHandler == null) {
            mHandler = new Handler(Looper.getMainLooper()) {
                @Override
                public void handleMessage(Message msg) {
                    if (mLogFragment != null) {
                        mLogFragment.showEntry((LogEntry)msg.obj);
                    }
                }
            };
        }
        Message msg = Message.obtain(mHandler, 0, entry);
        mHandler.sendMessage(msg);
    }
}
