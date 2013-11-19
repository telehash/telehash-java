package org.telehash.test;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.Node;
import org.telehash.core.Util;
import org.telehash.network.impl.InetEndpoint;
import org.telehash.storage.Storage;

public class StorageTest {

    private static final String SEEDS_JSON =
        "{ seeds: [ "+
            "{" +
                "publickey: \"" +
                    "30820122300d06092a864886f70d01010105000382010f003082010a02820101" +
                    "009a01802a3883774b1fea32da0040da402df12d7279b8e0f2c0fc50b68d6764" +
                    "06c3e0ef5fb2431da53b833ac5b384902b0738520f9dca20ddce51174f497864" +
                    "459191081b68be2d3e87fb37cf6e1ca6ce2635fe96d187c84b7d3393ee82d0d9" +
                    "6ce6eb6670b1b45607051b83824ca40843ff0fb437e9b4f8b8967757eed75e22" +
                    "21cd01aa9a00f413bac5a1982e13041241d88466758a89c0bd89d31e2b057534" +
                    "5fd2f4afe5e9e187333efe0c0934e5f17c593e7a7c7dc8338a0b05ede2339207" +
                    "1ca4d28d64348089115d9e9bf5c4a7d643b443916e2c7a682c4e21b57249c7fc" +
                    "925c41aeaaf40c4588a67c74adf1cc532e3f6ae0b7f5ef9c2c819d363eb1fd40" +
                    "ab0203010001\", "+
                "endpoint: \"inet:192.168.1.100/4242\" "+
            "}, "+
            "{" +
                "publickey: \"" +
                    "30820122300d06092a864886f70d01010105000382010f003082010a02820101" +
                    "008465a67530a90e4b0c13a56ef885599402fe1873765f58c4f13ac474dce145" +
                    "a41017069187f13368d2a7835e878bd9ce25cac9afee5ae2c07db4dfc95b6188" +
                    "60fa21e5448c893ea36c342f098b18b84eb79d1c9b54d6ea3599cfea2ff12e7d" +
                    "9a592eebf4463ac9e47ffea85b5452cb84eadde1512b4dda805875fc21bf3f50" +
                    "6819438f4f83ade7879641b47a6de7821f8e19674a6403407b1a72bd6c77a3b0" +
                    "0cbcd098cdbd304b25fb28798d77bcbda5052d5c763d154aa47a4d90e4a25c59" +
                    "2125caee10914c9d4a4128edbb985976b7373bf10ce6aad740f729881ee77882" +
                    "acb5c2739b327bb90f1818951f6ae64def1865dfb78382a5891aa18950d61489" +
                    "810203010001\", "+
                "endpoint: \"inet:192.168.1.101/4243\" "+
            "},"+                
            "{" +
                "publickey: \"" +
                    "30820122300d06092a864886f70d01010105000382010f003082010a02820101" +
                    "0092b1074b543232eedfb9ad523bdd93e2382385a5a115f459775d95d728bf7b" +
                    "fcb6b1a3a8bbc5555baa3a50be8a3ca96e32653f092ddd6f47fb7b6bc40e4965" +
                    "45bf470164061158f8bbec7d039c382b2ed14ee990c4a47782d0c7068c3e0f97" +
                    "b247cbc272e831d840b9b7ca080dd9bce3a926ea737a4e98955dc33c2734275e" +
                    "addf4963f75d552e4c70680b43e1546bd9ffb597535247561f0d10e1c36983f1" +
                    "4503c2b05680bd99947e625d91c1f3ef961ed0694c08ce7d99fb095d1b6bc421" +
                    "030359304df5059846268bbef4c6f1434e454add09909f0ab3234a5cfc9485e7" +
                    "31c9c52c5027bb9c764b32ab46f6ab9451ca0e696716eab45e12823cc73cf361" +
                    "f70203010001\", "+
                "endpoint: \"inet:192.168.1.102/4244\" "+
            "},"+                
        "]}";

    private Storage mStorage;

    @Before
    public void setUp() throws Exception {
        mStorage = Util.getStorageInstance();
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testParseSeeds() throws Exception {
        // create JSON seeds file
        File temp = File.createTempFile("seeds", "json");
        FileOutputStream fos = new FileOutputStream(temp);
        fos.write(SEEDS_JSON.getBytes("UTF-8"));
        fos.close();
        
        Set<Node> seeds = mStorage.readSeeds(temp.getAbsolutePath());
        assertNotNull(seeds);
        assertEquals(seeds.size(), 3);
        for (Node seed : seeds) {
            int port = ((InetEndpoint)seed.getEndpoint()).getPort();
            byte lowerOctet = ((InetEndpoint)seed.getEndpoint()).getAddress().getAddress()[3];
            if (port == 4242) {
                assertEquals(lowerOctet, 100);
            } else if (port == 4243) {
                assertEquals(lowerOctet, 101);
            } else if (port == 4244) {
                assertEquals(lowerOctet, 102);
            } else {
                fail("bad seed endpoint");
            }
        }
    }
}
