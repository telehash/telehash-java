package org.telehash.core;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

public class Log {

    private static final boolean ENABLE_COLOR = true;
    private static final String COLOR_RESET =
            new String(new char[] {0x1B, '[', '3', '9', ';', '4', '9', 'm'});
    private static final String COLOR_RED = new String(new char[] {0x1B, '[', '3', '1', 'm'});
    private static final String COLOR_GREEN = new String(new char[] {0x1B, '[', '3', '2', 'm'});
    private static final String COLOR_BLUE = new String(new char[] {0x1B, '[', '3', '4', 'm'});
    private static final String COLOR_MAGENTA = new String(new char[] {0x1B, '[', '5', '1', 'm'});
    private static final String COLOR_CYAN = new String(new char[] {0x1B, '[', '3', '6', 'm'});
    private static final String COLOR_YELLOW = new String(new char[] {0x1B, '[', '3', '3', 'm'});
    private static final String COLORS[] = new String[] {
        COLOR_RED, COLOR_GREEN, COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN
    };
    private static final Map<HashName,String> sColorMap = new HashMap<HashName,String>();

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

    public static void println(String msg, Object... args) {
        String tag;
        LocalNode localNode = Telehash.get().getLocalNode();

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

        if (ENABLE_COLOR) {
            if (localNode != null) {
                HashName hashName = localNode.getHashName();
                String color = sColorMap.get(hashName);
                if (color == null) {
                    int size = sColorMap.size();
                    if (size >= COLORS.length) {
                        color = COLOR_YELLOW;
                    } else {
                        color = COLORS[size];
                    }
                    sColorMap.put(hashName, color);
                }
                System.out.print(color);
            }
        }

        System.out.println(tag+String.format(msg, args));

        if (args.length > 0 && (args[args.length-1] instanceof Throwable)) {
            Throwable throwable = (Throwable)args[args.length - 1];

            StringWriter errors = new StringWriter();
            throwable.printStackTrace(new PrintWriter(errors));
            for (String line : errors.toString().split("\n")) {
                line.trim();
                System.out.println(tag+line);
            }
        }

        if (ENABLE_COLOR && localNode != null) {
            System.out.print(COLOR_RESET);
        }

    }
}
