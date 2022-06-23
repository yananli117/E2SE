package edu.sydney.e2se4j;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMacKDF {

    public static final String HDFK_SHA512 = "HMACSHA512";
    private final String hmacAlgorithm;
    private final byte[] prfKey;
    private final int hashLength;

    private static Mac getHmac(String hmacAlgorithm) {
        try {
            return Mac.getInstance(hmacAlgorithm);
        } catch (NoSuchAlgorithmException var2) {
            throw new IllegalArgumentException("Invalid HMAC algorithm");
        }
    }

    private static int getHashLen(String hmacAlgorithm) {
        return getHmac(hmacAlgorithm).getMacLength();
    }

    public HMacKDF(String hmacAlgorithm, byte[] inputKeyingMaterial) {
        this(hmacAlgorithm, inputKeyingMaterial, new byte[0]);
    }

    public HMacKDF(String hmacAlgorithm, byte[] inputKeyingMaterial, byte[] salt) {
        Mac hmac = getHmac(hmacAlgorithm);

        try {
            if (salt.length == 0) {
                hmac.init(new SecretKeySpec(new byte[getHashLen(hmacAlgorithm)], hmacAlgorithm));
            } else {
                hmac.init(new SecretKeySpec(salt, hmacAlgorithm));
            }
        } catch (InvalidKeyException var6) {
            throw new RuntimeException("Should not happen", var6);
        }

        this.hmacAlgorithm = hmacAlgorithm;
        this.prfKey = hmac.doFinal(inputKeyingMaterial);
        this.hashLength = hmac.getMacLength();

        assert this.hashLength == this.prfKey.length;

    }

    protected byte[] getPrfKey() {
        return (byte[]) this.prfKey.clone();
    }

    public byte[] createKey(int length) {
        return this.createKey(new byte[0], length);
    }

    public byte[] createKey(String info, int length) {
        return this.createKey(info.getBytes(StandardCharsets.UTF_8), length);
    }

    public byte[] createKey(byte[] info, int length) {
        if (length > 255 * this.hashLength) {
            throw new IllegalArgumentException("Provided length of " + length + " exceeds maximum of " + 255 * this.hashLength);
        } else {
            Mac hmac = getHmac(this.hmacAlgorithm);

            try {
                hmac.init(new SecretKeySpec(this.prfKey, this.hmacAlgorithm));
            } catch (InvalidKeyException var9) {
                throw new RuntimeException("Should not happen", var9);
            }

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] previousHash = new byte[0];

            byte[] collectedBytes;
            for (byte iteration = 1; bos.size() < length; ++iteration) {
                hmac.update(previousHash);
                hmac.update(info);
                hmac.update(iteration);
                collectedBytes = hmac.doFinal();
                bos.write(collectedBytes, 0, collectedBytes.length);
                previousHash = collectedBytes;
            }

            collectedBytes = bos.toByteArray();
            byte[] outputKeyingMaterial = new byte[length];
            System.arraycopy(collectedBytes, 0, outputKeyingMaterial, 0, length);
            return outputKeyingMaterial;
        }
    }
}
