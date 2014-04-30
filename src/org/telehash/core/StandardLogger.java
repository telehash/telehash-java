package org.telehash.core;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class StandardLogger implements LogListener {

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

    private static final boolean DEFAULT_ENABLE_COLOR = false;
    private static boolean sEnableColor = DEFAULT_ENABLE_COLOR;

    private static final String TMP_DIRECTORY = "/tmp";
    private static final String LOG_PATH = "/tmp/telehash.log";
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

    public static void setEnableColor(boolean enableColor) {
        sEnableColor = enableColor;
    }

    @Override
    public void onLogEvent(LogEntry entry) {
        if (entry == null) {
            return;
        }
        LocalNode localNode = entry.getTelehash().getLocalNode();

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

        String timestamp = String.format("%07.3f", (entry.getTime()/1000000000.0f));
        tag = timestamp + " " + tag;

        String color;
        String endColor;
        if (sEnableColor && localNode != null) {
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

        StringBuilder output = new StringBuilder();
        String text = entry.getMessage();
        for (String line : text.split("\n")) {
            if (! line.isEmpty()) {
                output.append(color+tag+line+endColor+"\n");
            }
        }

        Throwable error = entry.getError();
        if (error != null) {
            StringWriter errors = new StringWriter();
            error.printStackTrace(new PrintWriter(errors));
            for (String line : errors.toString().split("\n")) {
                line.trim();
                output.append(color+tag+line+endColor+"\n");
            }
        }

        String finalOutput = output.toString();
        for (PrintStream stream : sLogStreams) {
            stream.print(finalOutput);
        }
    }
}
