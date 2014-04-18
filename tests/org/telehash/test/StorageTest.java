package org.telehash.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.PeerNode;
import org.telehash.network.InetPath;
import org.telehash.storage.Storage;
import org.telehash.storage.impl.StorageImpl;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Set;

public class StorageTest {

    // Use this JSON structure to test the parsing of seeds.
    // This seeds file was taken from
    //     https://github.com/quartzjer/telehash-seeds/blob/master/seeds.json
    // and Java-stringified using the "stringinator.pl" tool found
    // elsewhere in this repository. The network paths have been
    // changed so that port numbers equal 9000 + the last octet of the
    // IPv4 address (for validation purposes).
    private static final String SEEDS_JSON =
        "{\n"+
        "  \"89a4cbc6c27eb913c1bcaf06bac2d8b872c7cbef626b35b6d7eaf993590d37de\": {\n"+
        "    \"admin\":\"http://github.com/quartzjer\",\n"+
        "    \"paths\": [{\n"+
        "      \"type\": \"ipv4\",\n"+
        "      \"ip\": \"208.68.164.253\",\n"+
        "      \"port\": 9253\n"+
        "    }, {\n"+
        "      \"type\": \"ipv6\",\n"+
        "      \"ip\": \"2605:da00:5222:5269:230:48ff:fe35:6572\",\n"+
        "      \"port\": 9253\n"+
        "    }, {\n"+
        "      \"type\": \"http\",\n"+
        "      \"http\": \"http://208.68.164.253:42424\"\n"+
        "    }],\n"+
        "    \"parts\": {\n"+
        "      \"2a\": \"beb07e8864786e1d3d70b0f537e96fb719ca2bbb4a2a3791ca45e215e2f67c9a\",\n"+
        "      \"1a\": \"6c0da502755941a463454e9d478b16bbe4738e67\"\n"+
        "    },\n"+
        "    \"keys\": {\n"+
        "      \"2a\": \"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJlhpi2pZZRrnf+bmnnRRAQHfzMz"+
                "DwOV+s+JzamyL0X9wwJK8m2DHCFcpJQSLFIzv3v+e102+pZlIWAU6vvO5s6J60C+9UwQoKj9L3cxUL/X"+
                "mEBjAnbwfs+61HGSjf8yS8Uon/0oDXxssJyJjnrzAJT7K5G+Nqf5N5IJiEfhYkfa9wkhWR4fU1ZiC3PZ"+
                "ZoMrGurGxWAwIs4No2LlBkZXUtAC31jISWODBAahGcaRjPgHFVaDxQ+gEQFse0Aa0mWA7KCRiSbBC89B"+
                "rx837AREWFa7t14UAi01BLcPSkbAIbIv1SmM+E3k7HdN6rXTjz2h7Na5DOCS4z1LgujXW460WQIDAQAB"+
                "\",\n"+
        "      \"1a\": \"hhzKwBDYADu6gQdDrP2AgQJmAE5iIbEqpPmLLZI9w72rLTCCqob9sw==\"\n"+
        "    },\n"+
        "    \"bridge\": true\n"+
        "  },\n"+
        "  \"f50f423ce7f94fe98cdd09268c7e57001aed300b23020840a84a881c76739471\": {\n"+
        "    \"admin\":\"http://github.com/quartzjer\",\n"+
        "    \"paths\": [{\n"+
        "      \"type\": \"ipv4\",\n"+
        "      \"ip\": \"208.126.199.195\",\n"+
        "      \"port\": 9195\n"+
        "    }, {\n"+
        "      \"type\": \"ipv6\",\n"+
        "      \"ip\": \"2001:470:c0a6:3::10\",\n"+
        "      \"port\": 9195\n"+
        "    }, {\n"+
        "      \"type\": \"http\",\n"+
        "      \"http\": \"http://208.126.199.195:42424\"\n"+
        "    }],\n"+
        "    \"parts\": {\n"+
        "      \"2a\": \"8a5235d7cebb82d48a945e7c4b301efed40503d50ea1063464fe839b12278d93\",\n"+
        "      \"1a\": \"b3c9341ff5d11670c1e1c918ad51631b1251448a\"\n"+
        "    },\n"+
        "    \"keys\": {\n"+
        "      \"2a\": \"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5mWOu3o0chHcpcxPYX43fD6DTWGk"+
                "Cj09QaWerHbTX1Gua5eW8VdPOM/Ki21WEY2xcBa55/s37hIRP1XZveFiWgIXft9g/L+1AsF56cO0ZGnH"+
                "hrp5Wabrt+L5mVuWg2VcSAUQ/gdoSLmDRTdOc0ruzroIN4a4Wnfk6rwvFYq/LfTj2w5cBD3ziVts4XSi"+
                "cX9fnmWElrTKfGLWyC6W5ICbLZ0BmTt9CZLbdNmotuYqQkPXPJ0wccsWAuI8yjbmU2my+F+vakWbGFvM"+
                "SCBlLlQLXMTnLbLtgnwgeujTHiJaB0Iycw5Q9FS0RiQ0QeFqUvmMX9BezKfayq2hHjcob58WbwIDAQAB"+
                "\",\n"+
        "      \"1a\": \"idT0VmmEmSdDF1eMrajIVHP0XZ/8Udgeas1Zxy0va5tD/KP393Ri3w==\"\n"+
        "    },\n"+
        "    \"bridge\": true\n"+
        "  }\n"+
        "}\n";
    private static final int NUM_SEEDS = 2;

    private Storage mStorage;

    @Before
    public void setUp() throws Exception {
        mStorage = new StorageImpl();
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

        Set<PeerNode> seeds = mStorage.readSeeds(temp.getAbsolutePath());
        assertNotNull(seeds);
        assertEquals(seeds.size(), NUM_SEEDS);
        for (PeerNode seed : seeds) {
            int port = ((InetPath)seed.getPath()).getPort();
            int lowerOctet = ((InetPath)seed.getPath()).getAddress().getAddress()[3]&0xFF;
            assertEquals(lowerOctet, port-9000);
        }
    }
}
