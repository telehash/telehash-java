package org.telehash.core;

import org.json.JSONObject;
import org.telehash.crypto.Crypto;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

@SuppressWarnings("serial")
public class FingerprintSet extends TreeMap<CipherSetIdentifier,byte[]> {

    private final HashName mHashName;
    private boolean mReadOnly = false;

    public FingerprintSet(Map<CipherSetIdentifier,byte[]> fingerprints) {
        putAll(fingerprints);
        mHashName = calculateHashNameFromFingerprints(this);
        mReadOnly = true;
    }

    public FingerprintSet(JSONObject json) {
        // parse the "from" fingerprints
        Iterator<?> fromIterator = json.keys();
        while (fromIterator.hasNext()) {
            String key = (String)fromIterator.next();
            String value = json.getString(key);
            byte[] csidBuffer = Util.hexToBytes(key);
            if (csidBuffer == null || csidBuffer.length != 1 || csidBuffer[0] == 0) {
                throw new IllegalStateException("invalid cipher set id in fingerprints");
            }
            CipherSetIdentifier csid = new CipherSetIdentifier(csidBuffer[0]);
            byte[] fingerprint = Util.hexToBytes(value);
            put(csid, fingerprint);
        }
        mHashName = calculateHashNameFromFingerprints(this);
        mReadOnly = true;
    }

    public HashName getHashName() {
        return mHashName;
    }

    public static CipherSetIdentifier bestCipherSet(FingerprintSet a, FingerprintSet b) {
        if (a == null || b == null) {
            return null;
        }
        CipherSetIdentifier best = null;
        for (CipherSetIdentifier csid : a.keySet()) {
            if (b.containsKey(csid)) {
                best = csid;
            }
        }
        return best;
    }

    private static HashName calculateHashNameFromFingerprints(
            Map<CipherSetIdentifier,byte[]> fingerprints
    ) {
        Crypto crypto = Telehash.get().getCrypto();
        byte[] hashNameBytes = null;
        // compose the hash name
        for (Map.Entry<CipherSetIdentifier,byte[]> entry : fingerprints.entrySet()) {
            CipherSetIdentifier csid = entry.getKey();
            byte[] fingerprint = entry.getValue();
            String fingerprintString = Util.bytesToHex(fingerprint);
            byte[] csidHexBytes;
            byte[] fingerprintHexBytes;
            try {
                csidHexBytes = csid.asHex().getBytes("UTF-8");
                fingerprintHexBytes = fingerprintString.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                // this never happens
                throw new RuntimeException("UTF-8 not supported");
            }

            // add this csid/fingerprint to the hash
            if (hashNameBytes == null) {
                hashNameBytes = crypto.sha256Digest(csidHexBytes);
            } else {
                hashNameBytes = crypto.sha256Digest(
                        Util.concatenateByteArrays(hashNameBytes, csidHexBytes)
                );
            }
            hashNameBytes = crypto.sha256Digest(
                    //Util.bytesToHex(hashNameBytes)+fingerprintString
                    Util.concatenateByteArrays(hashNameBytes, fingerprintHexBytes)
            );
        }
        return new HashName(hashNameBytes);
    }

    public JSONObject toJSON() {
        JSONObject json = new JSONObject();
        for (Map.Entry<CipherSetIdentifier,byte[]> entry : entrySet()) {
            json.put(entry.getKey().asHex(), Util.bytesToHex(entry.getValue()));
        }
        return json;
    }

    public String toJSONString() {
        return toJSON().toString();
    }

    @Override
    public String toString() {
        return toJSONString();
    }

    // override write methods to enforce read-only

    @Override
    public void clear() {
        throw new UnsupportedOperationException("read-only");
    }

    @Override
    public byte[] put(CipherSetIdentifier csid, byte[] v) {
        if (mReadOnly) {
            throw new UnsupportedOperationException("read-only");
        } else {
            return super.put(csid, v);
        }
    }

    @Override
    public void putAll(Map<? extends CipherSetIdentifier,? extends byte[]> m) {
        if (mReadOnly) {
            throw new UnsupportedOperationException("read-only");
        } else {
            super.putAll(m);
        }
    }

    @Override
    public byte[] remove(Object o) {
        throw new UnsupportedOperationException("read-only");
    }

    // Java identity

    @Override
    public int hashCode() {
        return mHashName.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        FingerprintSet other = (FingerprintSet) obj;
        if (mHashName == null) {
            if (other.mHashName != null)
                return false;
        } else if (!mHashName.equals(other.mHashName))
            return false;
        return true;
    }
}
