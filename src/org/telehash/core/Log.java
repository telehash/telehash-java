package org.telehash.core;

import java.io.PrintWriter;
import java.io.StringWriter;

public class Log {
    
    public static void d(String msg, Object... args) {
        println(msg, args);
    }
    public static void v(String msg, Object... args) {
        println(msg, args);
    }
    public static void i(String msg, Object... args) {
        println(msg, args);
    }
    public static void e(String msg, Object... args) {
        println(msg, args);
    }
    
    public static void println(String msg, Object... args) {
        String tag;
        Identity identity = Telehash.get().getIdentity();
        if (identity == null) {
            tag = "[        ] ";
        } else {
            byte[] hashName = identity.getHashName();
            int a = hashName[0] & 0xFF;
            int b = hashName[1] & 0xFF;
            int c = hashName[2] & 0xFF;
            int d = hashName[3] & 0xFF;
            tag = String.format("[%02x%02x%02x%02x] ", a,b,c,d);
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
        
    }
}
