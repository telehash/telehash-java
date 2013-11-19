package org.telehash.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.telehash.crypto.Crypto;
import org.telehash.crypto.impl.CryptoImpl;
import org.telehash.network.Network;
import org.telehash.network.impl.NetworkImpl;
import org.telehash.storage.Storage;
import org.telehash.storage.impl.StorageImpl;

/**
 * This class contains various static utility methods used throughout
 * the library.
 */
public class Util {
    
    private static int IO_BUFFER_SIZE = 4096;
    
    // poor man's dependency injection: static fields.
    // TODO: come up with a better way
    private static Crypto sCrypto;
    private static Storage sStorage;
    private static Network sNetwork;

    /**
     * Return a usable implementation of the Crypto interface.
     * 
     * @return the Crypto implementation.
     */
    public static Crypto getCryptoInstance() {
        if (sCrypto == null) {
            sCrypto = new CryptoImpl();
        }
        return sCrypto;
    };

    /**
     * Return a usable implementation of the Storage interface.
     *
     * @return the Storage implementation.
     */
    public static Storage getStorageInstance() {
        if (sStorage == null) {
            sStorage = new StorageImpl();
        }
        return sStorage;
    }

    /**
     * Return a usable implementation of the Network interface.
     *
     * @return the Network implementation.
     */
    public static Network getNetworkInstance() {
        if (sNetwork == null) {
            sNetwork = new NetworkImpl();
        }
        return sNetwork;
    }

    /**
     * Encode the provided byte array as a string of hex digits.
     * 
     * @param buffer The byte array to encode.
     * @return The string of hex digits.
     */
    public static String bytesToHex(byte[] buffer) {
        StringBuilder sb = new StringBuilder();
        for (byte b : buffer) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Decode the provided hex string into a byte array.
     * 
     * @param hex The hex string to decode.
     * @return The decoded byte array.
     */
    public static byte[] hexToBytes(String hex) {
        int hexLength = hex.length(); 
        if (hexLength % 2 != 0) {
            return null;
        }
        byte[] buffer = new byte[hexLength/2];
        int accumulator = 0;
        for (int i=0, j=0; i<hexLength; i++) {
            char c = hex.charAt(i);
            int v = 0;
            if (c >= '0' && c <= '9') {
                v = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                v = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                v = c - 'A' + 10;
            } else {
                // illegal character
                return null;
            }
            if (i%2==0) {
                accumulator = v << 4;
            } else {
                buffer[j] = (byte)(accumulator | v); 
                j++;
            }
        }
        return buffer;
    }
    
    /**
     * Read an entire file at once and return the contents.  This should
     * only be used for very small files.
     * 
     * @param filename The filename of the file to read.
     * @return A byte array of the file's contents.
     * @throws IOException If a problem happened while reading the file.
     */
    public static byte[] slurpFile(String filename) throws IOException {
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        byte[] buffer = new byte[IO_BUFFER_SIZE];
        int nbytes;
        while ((nbytes = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, nbytes);
        }
        
        fis.close();
        baos.close();
        return baos.toByteArray();
    }
    
    /**
     * Read an entire UTF-8 text file at once and return the contents
     * as a string.  This should only be used for very small files.
     * 
     * @param filename The filename of the file to read.
     * @return The contents of the file as a string.
     * @throws IOException If a problem happened while reading the file.
     */
    public static String slurpTextFile(String filename) throws IOException {
        return new String(slurpFile(filename), "UTF-8");
    }
}
