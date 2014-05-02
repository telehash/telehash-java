package org.telehash.androiddemo;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;

import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.LocalNode;
import org.telehash.core.SeedNode;
import org.telehash.core.Switch;
import org.telehash.core.Telehash;
import org.telehash.core.TelehashException;
import org.telehash.core.Util;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.storage.Storage;
import org.telehash.storage.impl.StorageImpl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.Set;

public class TelehashService extends Service {

    private static final String TAG = "Telehash";
    private static final String LOCALNODE_BASE_FILENAME = "telehash-node";
    private static final int PORT = 42424;

    public class TelehashBinder extends Binder {
        TelehashService getService() {
            return TelehashService.this;
        }
    }
    private final IBinder mBinder = new TelehashBinder();

    private String mLocalNodeBaseFilename;
    private Telehash mTelehash;
    private Switch mSwitch;

    private AndroidLogger mLogger = new AndroidLogger();

    public AndroidLogger getLogger() {
        return mLogger;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public void onCreate() {
        org.telehash.core.Log.setLogListener(mLogger);
        mLocalNodeBaseFilename =
                getFilesDir()+File.separator+LOCALNODE_BASE_FILENAME;

        Storage storage = new StorageImpl();

        // load or create a local node
        LocalNode localNode;
        try {
            localNode = storage.readLocalNode(mLocalNodeBaseFilename);
        } catch (TelehashException e) {
            if (e.getCause() instanceof FileNotFoundException) {
                // no local node found -- create a new one.
                try {
                    localNode = Telehash.get().getCrypto().generateLocalNode();
                    storage.writeLocalNode(localNode, mLocalNodeBaseFilename);
                } catch (TelehashException e1) {
                    e1.printStackTrace();
                    return;
                }
            } else {
                e.printStackTrace();
                return;
            }
        }

        System.out.println("my hash name: "+localNode.getHashName());

        File seedsJson = new File(getFilesDir()+File.separator+"seeds.json");
        if (! seedsJson.exists()) {
            try {
                writeSeedsJson(seedsJson);
            } catch (IOException e) {
                Log.e(TAG, "cannot write seeds.json", e);
                return;
            }
        }

        Set<SeedNode> seeds = null;
        try {
            seeds = storage.readSeeds(seedsJson.getAbsolutePath());
        } catch (TelehashException e) {
            Log.e(TAG, "cannot read seeds", e);
            return;
        }

        // debug seeds
        System.out.println("seeds:");
        for (SeedNode seed : seeds) {
            System.out.println("  hn " + seed.getHashName());
            for (Map.Entry<CipherSetIdentifier, byte[]> entry : seed
                    .getFingerprints().entrySet()) {
                System.out.println("    cs" + entry.getKey() + " fingerprint: "
                        + Util.bytesToHex(entry.getValue()));
            }
            for (CipherSetIdentifier csid : seed.getCipherSetIds()) {
                System.out.println("    cs " + csid);
                try {
                    HashNamePublicKey publicKey = seed.getPublicKey(csid);
                    if (publicKey != null) {
                        System.out.println("      pub: "
                                + Util.base64Encode(seed.getPublicKey(csid)
                                        .getEncoded()));
                        System.out.println("      fpr: "
                                + Util.bytesToHex(seed.getPublicKey(csid)
                                        .getFingerprint()));
                    }
                } catch (TelehashException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }

        // launch the switch
        mTelehash = new Telehash(localNode);
        mSwitch = new Switch(mTelehash, seeds, PORT);
        mTelehash.setSwitch(mSwitch);
        try {
            mSwitch.start();
            mSwitch.waitForInit();
        } catch (TelehashException e) {
            Log.e(TAG, "cannot start telehash", e);
            return;
        }
        Log.i(TAG, "telehash started.");
    }

    @Override
    public void onDestroy() {
        if (mSwitch != null) {
            mSwitch.stop();
        }
    }

    private static final String DEFAULT_SEEDS_JSON =
        "{\n"+
        "  \"ce9d2cfccf34345b1c1a1c5b6c72cb0cf625ec88cdc64b54921303b26a655949\": {\n"+
        "    \"admin\":\"http://github.com/quartzjer\",\n"+
        "    \"paths\": [\n"+
        "      {\n"+
        "        \"type\": \"http\",\n"+
        "        \"http\": \"http://208.68.164.253:42424\"\n"+
        "      },\n"+
        "      {\n"+
        "        \"type\": \"ipv4\",\n"+
        "        \"ip\": \"208.68.164.253\",\n"+
        "        \"port\": 42424\n"+
        "      },\n"+
        "      {\n"+
        "        \"type\": \"ipv6\",\n"+
        "        \"ip\": \"2605:da00:5222:5269:230:48ff:fe35:6572\",\n"+
        "        \"port\": 42424\n"+
        "      }\n"+
        "    ],\n"+
        "    \"parts\": {\n"+
        "      \"3a\": \"61b979399a285ec8a7159ea75f2953090612f26fe8ec80b4bdd3d746c7cba1f8\",\n"+
        "      \"2a\": \"df99cf38a79eb730b7b5c583faa4bcb21ccb044b5548df27837e608a3da8c57a\",\n"+
        "      \"1a\": \"4dd170c2523653dfaca8d2eca6c10ef4f703b3a95f4b77f57b81476d037e40b1\"\n"+
        "    },\n"+
        "    \"keys\": {\n"+
        "      \"3a\": \"azQ23XvFzj3238HlcUNsnIntl5VJY7ABMSQZWB6SFgo=\",\n"+
        "      \"2a\": \"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6mvKCqjGj7PI2o+NXLRdgwDXx982"+
                "71HN01ut873FrbJ4kkk3OmA//TpYTRKaE6xmeetXZnocci4q6X09TbfKpm2eNK0d898vWiYpGiRvQuy/"+
                "5nUGM2bge3CPOS3wQZWv5ZSvpRkhGufekzCg5p6WpdUG0u9D382E9LzdLidFnzHvIdfp0eOc2EMcX7/J"+
                "Sj5w7BbwsXfZNaWpOkUAQEYfPi/qF/teo0y8cTh70JVufCRDx+2/FtA/c8+JpjtgeCZoFO3bYuKjCQiY"+
                "mm4Zqcu1A6DYttCPkSKPXjirn9pdZFZBRH7IS7Mj5AJo2/L9nFYyLAE5xwMpBCE2rCY6wyzs7wIDAQAB"+
                "\",\n"+
        "      \"1a\": \"vRQvjqB6PM7QevqIW2YF3hY/AgDlhP7d0YDo1H6dZJAcYxbcsS/1Qw==\"\n"+
        "    }\n"+
        "  }\n"+
        "}\n";

    private void writeSeedsJson(File file) throws IOException {
        PrintWriter out = new PrintWriter(file);
        out.write(DEFAULT_SEEDS_JSON);
        out.close();
    }

}
