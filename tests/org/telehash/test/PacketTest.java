package org.telehash.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.telehash.core.CipherSetIdentifier;
import org.telehash.core.Identity;
import org.telehash.core.LineIdentifier;
import org.telehash.core.Node;
import org.telehash.core.OpenPacket;
import org.telehash.core.Packet;
import org.telehash.core.Telehash;
import org.telehash.core.Util;
import org.telehash.crypto.Crypto;
import org.telehash.crypto.HashNamePublicKey;
import org.telehash.crypto.LineKeyPair;
import org.telehash.network.Path;

public class PacketTest {

    private static final byte[] IDENTITY_PUBLIC_KEY = Util.base64Decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxH9lSUkd++wMBizH1Ot"+
            "JUf2MT6XpSH2VVc73sYWhetINckL4xhtozWY2VUfSrPt0a0DgZtyWhVh1Tlzhy4p"+
            "l31OYlTv/H0BLtKd2HrSsJUZSNeX8kp4KC0siU98AnZitA4misBvnJ+s/xXSZsWd"+
            "CAbCPxwkDgWt9cgQX4iiKo3DV5/960m8N4rfeViMjb24na8unJERDVn1YcEossHC"+
            "rl4a0BJOxqkQElriUler0SwEgO//5KxU66LLxHmXAy2tA630j6e7XLHSfOWVwivo"+
            "mGSKfI7k4dG1SznBXl3sa9Ibq66XRtltrattn+mW6sQ2GB0DiggDeEoLCqhz1ICj"+
            "CwIDAQAB"
    );

    private static final byte[] IDENTITY_PRIVATE_KEY = Util.base64Decode(
            "MIIEpQIBAAKCAQEAvxH9lSUkd++wMBizH1OtJUf2MT6XpSH2VVc73sYWhetINckL"+
            "4xhtozWY2VUfSrPt0a0DgZtyWhVh1Tlzhy4pl31OYlTv/H0BLtKd2HrSsJUZSNeX"+
            "8kp4KC0siU98AnZitA4misBvnJ+s/xXSZsWdCAbCPxwkDgWt9cgQX4iiKo3DV5/9"+
            "60m8N4rfeViMjb24na8unJERDVn1YcEossHCrl4a0BJOxqkQElriUler0SwEgO//"+
            "5KxU66LLxHmXAy2tA630j6e7XLHSfOWVwivomGSKfI7k4dG1SznBXl3sa9Ibq66X"+
            "Rtltrattn+mW6sQ2GB0DiggDeEoLCqhz1ICjCwIDAQABAoIBAQC2zhGd1nFzxoD9"+
            "I0SNHlO0LYtgRhB0T3AM6m8/jqoR6q+ltfqHheGvmyHoHUbZBBju2OdX40+e3IJD"+
            "rLnZhdMJOzv5XGZXXYn6MEwQyEI37A7K4Gphx9n6Jm5L2R4+hOGef0Nk0QR4B1VO"+
            "oKQy67J38W97TgM43zo2wvjXTjRJHLuD+SHv38AZy9b16DQOzVw7ak89KHXS/KHT"+
            "4bfLHvhsI5MxR2liEui8LLRtODO/7FyZIUiFT3JNCorg3EYadKomxA4YaO7hxTcW"+
            "qo58DsTP3WeoV2aOxuIeO1yj6UVlIYDI8xs9ZeiZmpuuXypzlfqVrigmy+lJ7dmJ"+
            "ilMkbKNRAoGBAPSdmIGRFs4CCxpDaQrUzGUqZ2EkoFtkBpwaKI8wEamCSghkhqyO"+
            "oKddde5Nb/NgnwOGHyc7aNJM/RGnuk2AqY2ie+UYS44jsa105wwNMOuQk3yqqTTH"+
            "MUzv5j0o90wvK+zD/AjK/jcseSYu082UvtQ6Xm6AOKpH4/2d9NwGHOC/AoGBAMf2"+
            "caWuuwj0BPLGm+x3ovLAAJiIdeUU1QYBM8WkZotdGs+yB0ySaJrQhVkJRWzPLGT2"+
            "J1quBCelCaAZXr/XxSSRMTD78vMIGsC7yT6Uslf1zWoApBka11eawkE+0wkOo/RQ"+
            "oljZm/AHf9jb66PxUBShC+UU9sNwy9B+ziUPXUS1AoGAQz+EKrKZg18acEjx+tFP"+
            "s8w5iYJJN3bDPm0Ok3bSlDhGZBJG1++KCRjvj+joCw+YB576t41kntQdipoC5MWn"+
            "V1HBH9VTCCuV8CrAThbeSRSBB3ffdqwASLd3I388pUwelkO26S/tPXvTfoTHI7Bt"+
            "2eiGB3jmmyGScynWpBpmG/8CgYEAr4kE7Pf9Une8HE8DM8s2LTkljMFGFUp7UmEd"+
            "zKNsLW0XCzpyM+LWlwjz9lwwKLuZciuwEmduWEsFrxh2V5yXgGlAsIqMFJKJwaVX"+
            "nWs1QAgUQbi8VRl97nZ5joMTCQFkJiXeznaA8G306i7spadBsEpLwdbsZFcRZD7c"+
            "wiXBr30CgYEAnMYg1M0alFbtLJQN+B+xNCKf+49b6fOwLvkt1XnkFOMEWDnaHyst"+
            "TSkuDEy1LQU99Iw0xIdTj38VQEpYbPTM3DqdAQDnQ4a0j1NidRrzZGHDGZie90pi"+
            "d66vFcnmRXGncwTdoHInpdJAnYVfrcT6Nv2RUPWk55t4p8/4FevvO+s="
    );

    private static final byte[] IDENTITY_PUBLIC_KEY_2 = Util.base64Decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm4LytLuYiIvtv+Dcg27D"+
            "IFDvM+1zIBLVB3wrdwziRxwC0Z1Kqsu6rTi1TscU0UGxJz+xIn11ZQVONyDF7p0z"+
            "I4URwEoMRxMUzljWKm+woPbnV7vFTzOiRixoHbp1Ym8AalAzZ5PEyi89EoQufa4c"+
            "lTpxPuCrwwyv/DJHDDU6OjOIoDLCMy/UVP0/LxA1gPEnGOY+0+99E+tJ/srubqqT"+
            "yUmgdmXq/ATyCoGE4dkjE7kMjF7AVkt42ftnZldOaB/EEpCr8/PzHx8ZmySEZj/u"+
            "9YDlONfWJ1qDYzhcJystYT+szEJTxei9Z7fZzNOriTGTuRktMyP6CooeHdQx+Rae"+
            "fwIDAQAB"
    );

    private static final byte[] IDENTITY_PRIVATE_KEY_2 = Util.base64Decode(
            "MIIEogIBAAKCAQEAm4LytLuYiIvtv+Dcg27DIFDvM+1zIBLVB3wrdwziRxwC0Z1K"+
            "qsu6rTi1TscU0UGxJz+xIn11ZQVONyDF7p0zI4URwEoMRxMUzljWKm+woPbnV7vF"+
            "TzOiRixoHbp1Ym8AalAzZ5PEyi89EoQufa4clTpxPuCrwwyv/DJHDDU6OjOIoDLC"+
            "My/UVP0/LxA1gPEnGOY+0+99E+tJ/srubqqTyUmgdmXq/ATyCoGE4dkjE7kMjF7A"+
            "Vkt42ftnZldOaB/EEpCr8/PzHx8ZmySEZj/u9YDlONfWJ1qDYzhcJystYT+szEJT"+
            "xei9Z7fZzNOriTGTuRktMyP6CooeHdQx+RaefwIDAQABAoIBAH8Qvxl30wl3NDs9"+
            "E1D9Nsh3+Qt38EJ7wL7N8YHj8BvkQlVd7T2jG5QgKt0Eg/j7cTG9tBGXa02wyRj4"+
            "WWI/5iIWv8tbda65Y527Lrsb6bmMJLkl/vFZIjWuYSAxU2qrgi5b+7SdJAWEFaXE"+
            "hWxB0K8KQq/6yb2k50LtHepWr44PclsgRkc3Ddu1NfNDw40dMGZREM7yfdrEucxs"+
            "Fy5Fg7GTe2+Fhk+CBEeeRJRswwbbb0aa5bmjC52Cms2+XOZxRVYFNUQO7MttsKeQ"+
            "K6VMSy2FRLIDj+cmtV6dqwbZMv+eXGEvBpQMCR/NKRk5ma4uP8kDJLJxjJw9GNQe"+
            "N2aMbNkCgYEA9c9YiKt1PXmOgXx1ui6TZoexNX7W3j3nZd2XL4vC7DAUwbCu2NfH"+
            "RlEvhuYJUPjju0IZqUbjj4A6M9W2f+DumJfgT5Z88bWIDikO+BaSXBQ29qBkEFwl"+
            "aZ7ST4JOUGjEf2YEkn9X2z42fcUSckeFD01LL18OU6alj9nTL8jSVXsCgYEAofVP"+
            "w9x71n+hC3oUBEnZKuCWg4CYEvKXXMsFhLuJnURahc8Q+N2zWRPUfm1k4TpXJ7K3"+
            "k3DoonSWaH109c1d3sH4ibfQVT/VVh+NMpmKJY+20MNGtxlwrML5S7GaJlEG6B6/"+
            "ylDHgHNpv41qBRrzaPM8ji//G93YIWT7E/qBEc0CgYBO3MEIyAmLOY6Q2H9kxkCg"+
            "KnSeNx10m+O7eMZiiLJ22E4wfiD6jO/wDWf0HaVrhw55K5HUD1w+0+LYcn5ktKOX"+
            "7VIX9q4LVjRaZq3YxlUamZmwsnCoFwghxMSwoZvCjHpObUqWPajQPDt7SljKtUtp"+
            "R2ERx6tvBw4jAr2QnRtuNQKBgHWHts3UyA196xmQCsyd5rnl53Qgsrs1TsBpGGUd"+
            "Tx1QiDyIarGe+VLQQClLK6UCmFLXr76QdlHGN4w2VtU1pkRMEReny8jBnQh1txqc"+
            "L5NYent+6mdfT9QfXZgfl1TtAg0am2WvP0eo+XmnnuN7jl5//VbV39SSJhD93fK+"+
            "nEGVAoGAS6J1fAtQf5VE64Uqscw/o0pjWWBBOKNCooAqiMbBhYMaKEWbrgEB1heN"+
            "T2DNGXL0C6bHiZOspB6HWbBVebczlWoFSR0Ow6kIuSMm2nq6OeaX6URBqCQ2F8gr"+
            "avWco0OFhsp/yUegAK0qxLSuzFELjSYrydSrYyd0rnPlu/U+u00="
    );

    private static final byte[] DESTINATION_PUBLIC_KEY = Util.base64Decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgBnwwPNTOA+0dljOzjfc"+
            "fDGVs61U328CXCFzvDCDfFVYMBuoiOI8O9W5Ydfgcyd7N6hjxW8tQU7ZXfq6SoTT"+
            "AtxmLzqiIewtR7lKdhzT3RfNn8NmhpDgko7cb+Am6jNQZvx3jM5O1eQQoAUvAaIO"+
            "ooJouF1vDhainN3EYSwNPXM+4NWA6Ls0Pl0DbPtfXY+H9dv2zkAiD3nP8lJlxOTD"+
            "3oHDKQbaGiNLUcFCKCEJvLL9e5bBu15phYHONfkiIwqchPbalo8i67JTdW5a2ipd"+
            "UyQW6cnGmooeHuN5lq9NDUTF0HPFvl50NdwMAp0sCt5UoCdIjOHGbvExxeSCG121"+
            "2wIDAQAB"
    );

    private static final byte[] TEST_LINE_ID = Util.hexToBytes(
            "85eb5ccb0878bafd5e1623883a91cf4f"
    );

    private static final byte[] TEST_OPEN_PARAMETER = Util.base64Decode(
            "d9O8ZGD68l99rLwfZcAIVvptAFpaENcA0EytoRkM0jDCR9VBuv312YicIM1F2Th7" +
            "hCZ7J0QxfrXc+cA+ao+vNJO47pN+CFveLX0AqPsI6q7eAjEqqsdtcOwqP48YH1hK" +
            "iePtivErVpuNJIVA9hXKQdpgGwYaAsDC8U/lpzi2vVGxkb29RYHrz5seWJ+u5HFN" +
            "74eQYIDRQrAWuPK8l/xSYsBbGncCXwSiVT6BOCD4xy7c5dYzqO5I6nTK8fqURoET" +
            "IO4N/0wm8guXJtc3jOJhUREsLWsl+wf+dBR87Jn1g7Zxs/kHkt0XyNox9062lhiK" +
            "saB3pQRYd+F8l4A5vzjUAw=="
    );

    private static final long TEST_OPEN_TIME = 1385581521161L;

    private static LineKeyPair mECKeyPair;
    private static final byte[] TEST_EC_PUBLIC_KEY =
            Util.hexToBytes(
                    "7878818c43ce15c7cfe8831257d520f6834d4b55e8c3a545ba4e6e563fc40a672e0" +
                    "f6e1a1a33a229cc7241f539d3f10f4576607590954098b5ff41c1b23780ac"
            );
    private static final byte[] TEST_EC_PRIVATE_KEY =
            Util.hexToBytes("a8259e94d600277fe865ca9efca87b4d341a8496e15b17a79121d89054b48da1");

    private static final byte[] EXPECTED_PACKET_SHA256 =
            Util.hexToBytes("3e434d6a5e6ee2ee47712ececa9a8f5fbd47d1f071d889805ec253dfd1be5f80");

    private static final String SAMPLE_PATH =
            "{\"type\": \"ipv4\", \"ip\": \"127.0.0.1\", \"port\": 4242}";

    private Crypto mCrypto;
    private Identity mIdentity;
    private Identity mIdentity2;
    private Telehash mTelehash = new Telehash();
    private Telehash mTelehash2 = new Telehash();

    @Before
    public void setUp() throws Exception {
        mCrypto = mTelehash.getCrypto();

        mIdentity = new Identity(
                mCrypto.createHashNameKeyPair(
                        mCrypto.decodeHashNamePublicKey(IDENTITY_PUBLIC_KEY),
                        mCrypto.decodeHashNamePrivateKey(IDENTITY_PRIVATE_KEY)
                )
        );
        mTelehash.setIdentity(mIdentity);

        mIdentity2 = new Identity(
                mCrypto.createHashNameKeyPair(
                        mCrypto.decodeHashNamePublicKey(IDENTITY_PUBLIC_KEY_2),
                        mCrypto.decodeHashNamePrivateKey(IDENTITY_PRIVATE_KEY_2)
                )
        );
        mTelehash2.setIdentity(mIdentity2);

        mECKeyPair = mCrypto.createECKeyPair(
                mCrypto.decodeLinePublicKey(TEST_EC_PUBLIC_KEY),
                mCrypto.decodeLinePrivateKey(TEST_EC_PRIVATE_KEY)
        );
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testOpenPacket() throws Exception {
        HashNamePublicKey destinationPublicKey =
                mCrypto.decodeHashNamePublicKey(DESTINATION_PUBLIC_KEY);
        Node remoteNode = new Node(
                destinationPublicKey,
                Path.parsePath(SAMPLE_PATH)
        );

        CipherSetIdentifier csid = Telehash.get().getCrypto().getCipherSet().getCipherSetId();
        OpenPacket openPacket = new OpenPacket(mIdentity, remoteNode, csid);

        openPacket.setLinePublicKey(mECKeyPair.getPublicKey());
        openPacket.setLinePrivateKey(mECKeyPair.getPrivateKey());
        openPacket.setOpenTime(TEST_OPEN_TIME);
        openPacket.setLineIdentifier(new LineIdentifier(TEST_LINE_ID));

        byte[] openPacketBuffer = openPacket.render(
                TEST_OPEN_PARAMETER
        );
        assertNotNull(openPacketBuffer);
        assertArrayEquals(
                EXPECTED_PACKET_SHA256,
                mTelehash.getCrypto().sha256Digest(openPacketBuffer)
        );
    }

    @Test
    public void testOpenPacketParse() throws Exception {
        Path localPath = Path.parsePath(SAMPLE_PATH);
        Path remotePath = Path.parsePath(SAMPLE_PATH);
        Node remoteNode = new Node(
                mIdentity2.getPublicKey(),
                remotePath
        );
        CipherSetIdentifier csid = Telehash.get().getCrypto().getCipherSet().getCipherSetId();
        OpenPacket openPacket = new OpenPacket(mIdentity, remoteNode, csid);
        byte[] openPacketBuffer = openPacket.render();
        assertNotNull(openPacketBuffer);

        Packet packet = Packet.parse(mTelehash2, openPacketBuffer, localPath);
        assertNotNull(packet);
        assertTrue(packet instanceof OpenPacket);
        OpenPacket openPacket2 = (OpenPacket)packet;
        assertEquals(
                openPacket.getLinePublicKey(),
                openPacket2.getLinePublicKey()
        );
        assertEquals(openPacket.getOpenTime(), openPacket2.getOpenTime());
        assertEquals(openPacket.getLineIdentifier(), openPacket2.getLineIdentifier());
    }

}
