package org.telehash.crypto.set2a;

import org.spongycastle.crypto.util.PublicKeyFactory;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;

public class RSAUtils {

    private static final String RSA_PRIVATE_KEY_PEM_TYPE = "RSA PRIVATE KEY";
    private static final String RSA_PUBLIC_KEY_PEM_TYPE = "PUBLIC KEY";

    /**
     * Parse a PEM-formatted RSA public key
     *
     * @param pem The PEM string.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public static HashNamePublicKey parseRSAPublicKeyFromStorage(
            String pem
    ) throws TelehashException {
        try {
            PemReader pemReader = new PemReader(new StringReader(pem));
            PemObject pemObject = pemReader.readPemObject();
            pemReader.close();
            if (pemObject == null) {
                throw new TelehashException("cannot parse RSA public key PEM file.");
            }
            if (! pemObject.getType().equals(RSA_PUBLIC_KEY_PEM_TYPE)) {
                throw new TelehashException(
                        "RSA public key PEM file of incorrect type \"" +
                        pemObject.getType() + "\""
                );
            }
            return new HashNamePublicKeyImpl(PublicKeyFactory.createKey(pemObject.getContent()));
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Read an RSA public key from a file.
     *
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public static HashNamePublicKey readRSAPublicKeyFromFile(
            String filename
    ) throws TelehashException {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filename));
            String line = reader.readLine();
            reader.close();
            return new HashNamePublicKeyImpl(Util.base64Decode(line));
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Read an RSA private key from a file.
     *
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public static HashNamePrivateKey readRSAPrivateKeyFromFile(
            String filename
    ) throws TelehashException {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filename));
            String line = reader.readLine();
            reader.close();
            return new HashNamePrivateKeyImpl(Util.base64Decode(line));
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Write an RSA public key to a file.
     *
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws IOException If a problem occurs while reading the file.
     */
    public static void writeRSAPublicKeyToFile(
            String filename,
            HashNamePublicKey key
    ) throws TelehashException {
        try {
            FileWriter fileWriter = new FileWriter(filename);
            fileWriter.write(Util.base64Encode(key.getEncoded()));
            fileWriter.write("\n");
            fileWriter.close();
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Write an RSA private key to a file.
     *
     * @param filename The filename of the file to write.
     * @param key The key to write.
     * @throws IOException If a problem occurs while reading the file.
     */
    public static void writeRSAPrivateKeyToFile(
            String filename,
            HashNamePrivateKey key
    ) throws TelehashException {
        try {
            FileWriter fileWriter = new FileWriter(filename);
            fileWriter.write(Util.base64Encode(key.getEncoded()));
            fileWriter.write("\n");
            fileWriter.close();
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }
}
