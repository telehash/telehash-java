package org.telehash.core;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;

public class Log {

    private static final boolean ENABLE_COLOR = true;
    private static final String ESCAPE = new String(new char[] {0x1B});
    private static final String COLOR_RESET = ESCAPE + "[39;49m";
    private static final String COLOR_RED = ESCAPE + "[31m";
    private static final String COLOR_GREEN = ESCAPE + "[32m";
    private static final String COLOR_BLUE = ESCAPE + "[34m";
    private static final String COLOR_MAGENTA = ESCAPE + "[35m";
    private static final String COLOR_CYAN = ESCAPE + "[36m";
    private static final String COLOR_YELLOW = ESCAPE + "[33m";
    private static final String COLOR_RED_BOLD = ESCAPE + "[31;1m";
    private static final String COLOR_GREEN_BOLD = ESCAPE + "[32;1m";
    private static final String COLOR_BLUE_BOLD = ESCAPE + "[34;1m";
    private static final String COLOR_MAGENTA_BOLD = ESCAPE + "[35;1m";
    private static final String COLOR_CYAN_BOLD = ESCAPE + "[36;1m";
    private static final String COLOR_YELLOW_BOLD = ESCAPE + "[33;1m";
    private static final String COLORS[] = new String[] {
        COLOR_RED, COLOR_GREEN, COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_YELLOW,
        COLOR_RED_BOLD, COLOR_GREEN_BOLD, COLOR_BLUE_BOLD, COLOR_MAGENTA_BOLD, COLOR_CYAN_BOLD,
        COLOR_YELLOW_BOLD
    };
    private static final Map<HashName,String> sColorMap = new HashMap<HashName,String>();

    private static Object sLock = new Object();

    private static final String TMP_DIRECTORY = "/tmp";
    private static final String LOG_PATH = "/tmp/telehash.log";
    private static long sStartTime = System.nanoTime();
    private static Set<PrintStream> sLogStreams = new HashSet<PrintStream>();
    static {
        sLogStreams.add(System.out);
        // on systems with a /tmp, store a copy of the log in /tmp/telehash.log
        // TODO: this is temporary, for early-stage development.
        if (new File(TMP_DIRECTORY).exists()) {
            try {
                sLogStreams.add(new PrintStream(LOG_PATH));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    public static void d(String msg, Object... args) {
        println(msg, args);
    }
    public static void v(String msg, Object... args) {
        println(msg, args);
    }
    public static void i(String msg, Object... args) {
        println(msg, args);
    }
    public static void w(String msg, Object... args) {
        println(msg, args);
    }
    public static void e(String msg, Object... args) {
        println(msg, args);
    }

    private static void println(String msg, Object... args) {
        if (msg == null || msg.isEmpty()) {
            return;
        }

        LocalNode localNode = Telehash.get().getLocalNode();

        String tag;
        if (localNode == null) {
            tag = "[        ] ";
        } else {
            byte[] hashName = localNode.getHashName().getBytes();
            int a = hashName[0] & 0xFF;
            int b = hashName[1] & 0xFF;
            int c = hashName[2] & 0xFF;
            int d = hashName[3] & 0xFF;
            tag = String.format("[%02x%02x%02x%02x] ", a,b,c,d);
        }

        long ts = System.nanoTime() - sStartTime;
        String timestamp = String.format("%07.3f", (ts/1000000000.0f));
        tag = timestamp + " " + tag;

        StringBuilder logEntry = new StringBuilder();
        String color;
        String endColor;
        if (ENABLE_COLOR && localNode != null) {
            HashName hashName = localNode.getHashName();
            color = sColorMap.get(hashName);
            if (color == null) {
                color = COLORS[Math.abs(hashName.hashCode()) % COLORS.length];
                sColorMap.put(hashName, color);
            }
            endColor = COLOR_RESET;
        } else {
            color = "";
            endColor = "";
        }

        String text = String.format(msg, args);
        for (String line : text.split("\n")) {
            if (! line.isEmpty()) {
                logEntry.append(color+tag+line+endColor+"\n");
            }
        }

        if (args.length > 0 && (args[args.length-1] instanceof Throwable)) {
            Throwable throwable = (Throwable)args[args.length - 1];

            StringWriter errors = new StringWriter();
            throwable.printStackTrace(new PrintWriter(errors));
            for (String line : errors.toString().split("\n")) {
                line.trim();
                logEntry.append(color+tag+line+endColor+"\n");
            }
        }

        synchronized (sLock) {
            LinkedList<String> buffer = sBuffer.get();
            if (buffer != null) {
                buffer.add(logEntry.toString());
            } else {
                print(logEntry.toString());
            }
        }
    }

    private static void print(String s) {
        synchronized (sLock) {
            for (PrintStream stream : sLogStreams) {
                stream.print(s);
            }
        }
    }

    private static ThreadLocal<LinkedList<String>> sBuffer = new ThreadLocal<LinkedList<String>>();

    public static void buffer() {
        synchronized (sLock) {
            LinkedList<String> buffer = sBuffer.get();
            if (buffer != null) {
                throw new IllegalStateException("buffer() called twice without flush().");
            }
            sBuffer.set(new LinkedList<String>());
        }
    }

    public static void flush() {
        synchronized (sLock) {
            LinkedList<String> buffer = sBuffer.get();
            if (buffer == null) {
                throw new IllegalStateException("flush() called without buffer().");
            }
            for (String s : buffer) {
                print(s);
            }
            sBuffer.remove();
        }
    }
}
