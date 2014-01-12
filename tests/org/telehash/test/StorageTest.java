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

    // Use this JSON structure to test the parsing of seeds.
    // Java-stringified using the following command line:
    // sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; $!s/$/\\n" +/; $s/$/\\n";/;' < seeds.json > seeds.txt
    // This seeds file was taken from
    //     https://github.com/telehash/thjs/blob/master/seeds.json
    // but the IPv4 port numbers have been changed to equal 9000 + the
    // last octet of the IPv4 address (for validation purposes).
    private static final String SEEDS_JSON =
        "[{\n" +
        "  \"ip\": \"208.68.164.253\",\n" +
        "  \"port\": 9253,\n" +
        "  \"ip6\": \"2605:da00:5222:5269:230:48ff:fe35:6572\",\n" +
        "  \"port6\": 42424,\n" +
        "  \"hashname\": \"5fa6f146d784c9ae6f6d762fbc56761d472f3d097dfba3915c890eec9b79a088\",\n" +
        "  \"pubkey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoQkh8uIPe18Ym5kO3VX\\nqPhKsc7vhrMMH8HgUO3tSZeIcowHxZe+omFadTvquW4az7CV/+3EBVHWzuX90Vof\\nsDsgbPXhzeV/TPOgrwz9B6AgEAq+UZ+cs5BSjZXXQgFrTHzEy9uboio+StBt3nB9\\npLi/LlB0YNIoEk83neX++6dN63C3mSa55P8r4FvCWUXue2ZWfT6qamSGQeOPIUBo\\n4aiN6P4Hzqaco6YRO9v901jV+nq0qp0yHKnxlIYgiY7501vXWceMtnqcEkgzX4Rr\\n7nIoA6QnlUMkTUDP7N3ariNSwl8OL1ZjsFJz7XjfIJMQ+9kd1nNJ3sb4o3jOWCzj\\nXwIDAQAB\\n-----END PUBLIC KEY-----\\n\",\n" +
        "  \"http\": \"http://208.68.164.253:42424\",\n" +
        "  \"bridge\": true\n" +
        "}, {\n" +
        "  \"ip\": \"173.255.220.185\",\n" +
        "  \"port\": 9185,\n" +
        "  \"ip6\": \"2600:3c01::f03c:91ff:fe70:ff59\",\n" +
        "  \"port6\": 42424,\n" +
        "  \"hashname\": \"b61120844c809260126aa0cf75390ef7f72c65a9ce03366efcf89ff549233758\",\n" +
        "  \"pubkey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4xkpFtu9IQc/WiWNHGgm\\nKnJ/TgiU9ltLLD4yJSu5LOiV5nH5lcjD8LPD4IgxPbOVKS/Xs2sosNqYsxVbSH60\\nJ5EOzc3okIdTLj0OhDoEhpwBXpnWzRCYOqlRSeF78yu2oWxdP1zA9nMC7laB2veA\\nDJ4KIaGKcs1uHesD5DGTGtPSHErove03HkMSlOBHpt239bNnv4XayQuwoRBsCoiT\\ntKTPRxkbDN7KQtHozuumwq0wSedYoJe4r0Z36V6UU9KNnFvz2QR+CdRn3idDOeYj\\nGnKFa5775fQGU5pwOk31u7J+gQ8h+tTQq6WZL5VaEeeFD6V4a6Zet2kBGhT6Z7h0\\nuQIDAQAB\\n-----END PUBLIC KEY-----\\n\"\n" +
        "}, {\n" +
        "  \"ip\": \"204.45.252.101\",\n" +
        "  \"port\": 9101,\n" +
        "  \"hashname\": \"6b171cedc8945ca7ba078392c0d1bc34fe0e7f161fc60e7b1cdb246f68bcb683\",\n" +
        "  \"pubkey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsXUyU223dwN5VbPZN9nn\\niiQ7gTcTK90ad83I+/Nd6M87QF0qwHuF+cQYeQP2aJEfgZsFVCVVwcjRUxjRaVX/\\nBSE4eKtIGazHr4idajkYka0No5hIJfw7p9INLZw6ALx4y9678sy2dyMAm0BHhY+A\\n4AzlFd0uO+I3MJKED5DF0baACLNu9VdNIaRQ/OQeL/Jl1b4VJF/yZ6FZGcyYGYF7\\nwf/ttSHMv1v1gCCC6o42Q2P67M+HpbPO1RD2IRrwmGI5Onmqp1bAqGmu4BMCfFsj\\nn/mCVJnVVC1GNiUWQY6n549j2y7Ow7JKmRGlWq2i+QWSGOUylZIvue+XIObY7/dv\\nPwIDAQAB\\n-----END PUBLIC KEY-----\\n\"\n" +
        "}, {\n" +
        "  \"ip\": \"208.126.199.195\",\n" +
        "  \"port\": 9195,\n" +
        "  \"ip6\": \"2001:470:c0a6:3::10\",\n" +
        "  \"port6\": 42424,\n" +
        "  \"hashname\": \"39c7f1d641947f51960ec5ab070680ea9dff110e8406cb07e4ae093a2e5d823a\",\n" +
        "  \"pubkey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAltxAjgqbG441oAiqwF0p\\nbJBUpPi06W1c0m3lrGg/h5nv5njiZq7s6LV9JZKPLINRk4UA4DdILBvOlKXG8/kQ\\n0fMxve8di8EFbsaUCKaZ5zFWFYv1FPKc6TU29zIyQEGoZIZfphnfFUvk7PIOBd3m\\nyEkncLBviFHVrfY3sDupni9ZOLGeAqpinQfuD1kmc3FbsZ+6j3A7QfMqlXI56jw3\\nZRKrXyVL6eudj2FHL0ZO70m+MC3AcUBzXtwyDIY9xowIrcp6+dfSyQncGqKKDF3H\\nqLRch+KpYrAZ6abHKjuN93tlIPyyKNCYQwex+j/UKN/5SlqDV8ctp4LwImCZQYGb\\nLwIDAQAB\\n-----END PUBLIC KEY-----\\n\",\n" +
        "  \"http\": \"http://208.126.199.195:42424\",\n" +
        "  \"bridge\": true\n" +
        "}, {\n" +
        "  \"ip\": \"162.243.1.152\",\n" +
        "  \"port\": 9152,\n" +
        "  \"hashname\": \"9ba9c175c3c26af9df5c8163ea91d4ae4eca59ba95d66deb287c89ea0c596979\",\n" +
        "  \"pubkey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnMrFnowz5jQAQrXSdj6M\\nZE8mqbWweXwc53oe0kNC+AmBCnobYkdL4ZXk8JiHxP+sNtaTxbEagdQohoqTX1Ap\\njjZ+pGt5Dcnqy1OfPMtUQyvEI1hL6xDU9msLPwK0NztHp1BlKeozppeBswNcPPxG\\nevAn6yd51dP+BcrRAM34G8C+TrnNQWmBTRob1eKifDS+80taVxma5jt2/JUHFTxo\\n2ualo4Wf/mScg8RXH4Pfhn7nIMBFQPom+58ERtORZWHl3aOty6It2inpPAx0PFBb\\nNzBbYRMLOkW7IYfTdXz+Y17pM6kEWK1Y5xUHGmxTMY4IZtvX2L5bTTMhAdSYgqSF\\nEQIDAQAB\\n-----END PUBLIC KEY-----\\n\"\n" +
        "}]\n";
    private static final int NUM_SEEDS = 5;

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
        assertEquals(seeds.size(), NUM_SEEDS);
        for (Node seed : seeds) {
            int port = ((InetEndpoint)seed.getEndpoint()).getPort();
            int lowerOctet = ((InetEndpoint)seed.getEndpoint()).getAddress().getAddress()[3]&0xFF;
            assertEquals(lowerOctet, port-9000);
        }
    }
}
