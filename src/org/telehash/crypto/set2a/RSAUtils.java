package org.telehash.crypto.set2a;

import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.telehash.core.TelehashException;
import org.telehash.crypto.HashNamePrivateKey;
import org.telehash.crypto.HashNamePublicKey;

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
     * Read a PEM-formatted RSA public key from a file.
     *
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public static HashNamePublicKey readRSAPublicKeyFromFile(
            String filename
    ) throws TelehashException {
        try {
            PemReader pemReader = new PemReader(new FileReader(filename));
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
     * Read a PEM-formatted RSA private key from a file.
     *
     * @param filename The filename of the file containing the PEM-formatted key.
     * @return The key.
     * @throws TelehashException If a problem occurs while reading the file.
     */
    public static HashNamePrivateKey readRSAPrivateKeyFromFile(
            String filename
    ) throws TelehashException {
        try {
            PemReader pemReader = new PemReader(new FileReader(filename));
            PemObject pemObject = pemReader.readPemObject();
            pemReader.close();
            if (pemObject == null) {
                throw new TelehashException("cannot parse RSA private key PEM file.");
            }
            if (! pemObject.getType().equals(RSA_PRIVATE_KEY_PEM_TYPE)) {
                throw new TelehashException(
                        "RSA private key PEM file of incorrect type \"" +
                        pemObject.getType() + "\""
                );
            }
            return new HashNamePrivateKeyImpl(pemObject.getContent());
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Write a PEM-formatted RSA public key to a file.
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
            PemWriter pemWriter = new PemWriter(new FileWriter(filename));
            PemObject pemObject = new PemObject(
                    RSA_PUBLIC_KEY_PEM_TYPE,
                    key.getEncoded()
            );
            pemWriter.writeObject(pemObject);
            pemWriter.close();
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }

    /**
     * Write a PEM-formatted RSA private key to a file.
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
            PemWriter pemWriter = new PemWriter(new FileWriter(filename));
            PemObject pemObject = new PemObject(
                    RSA_PRIVATE_KEY_PEM_TYPE,
                    key.getEncoded()
            );
            pemWriter.writeObject(pemObject);
            pemWriter.close();
        } catch (IOException e) {
            throw new TelehashException(e);
        }
    }
}
