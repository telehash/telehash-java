package org.telehash.core;

public class Log {
    public static void i(String msg, Object... args) {
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
    }
}
