package edu.sydney.e2se4j;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

/**
 * Author: Ya-Nan Li,
 */
public class Utils {
    private Utils() {
        throw new AssertionError();
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Convert Byte Array into Hex String
     *
     * @param bytes Byte Array
     * @return Hex String
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static int kdfBenchmark(int numIterations, int numBenchRepetitions) {

        byte[] randomBytes = new byte[10];
        Random rand = new Random();
        byte[] hash, cum_hash;
        long start = 0, tot = 0, elapsed = 0;
        String str;

        cum_hash = KDF(Constants.PASSWORD_SALT, "start", Constants.PASSWORD_SALT, Constants.HASHED_PASSWORD_LENGTH,
                numIterations);
        hash = KDF(Constants.PASSWORD_SALT, "start", Constants.PASSWORD_SALT, Constants.HASHED_PASSWORD_LENGTH,
                numIterations);

        for (int j = 0; j < numBenchRepetitions; j++) {
            rand.nextBytes(randomBytes);
            str = rand.toString();
            start = System.currentTimeMillis();
            hash = KDF(Constants.PASSWORD_SALT, str, Constants.PASSWORD_SALT, Constants.HASHED_PASSWORD_LENGTH,
                    numIterations);
            elapsed = System.currentTimeMillis();
            tot += elapsed - start;


            int i = 0;
            for (byte b : hash)
                cum_hash[i] = (byte) (b ^ cum_hash[i++]);
        }

        if (Arrays.equals(cum_hash, hash)) {
            throw new RuntimeException("Benchmark Failed");
        }
        return (int) (tot / numBenchRepetitions);
    }


    public static byte[] KDF(byte[] key, String passphrase, byte[] salt, int outputLength, int kdfHashRepetitions) {
        try {
            byte[] keyAndSalt = new byte[key.length + salt.length];
            System.arraycopy(salt, 0, keyAndSalt, 0, salt.length);
            System.arraycopy(key, 0, keyAndSalt, salt.length, key.length);

            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), keyAndSalt, kdfHashRepetitions, outputLength);
            SecretKeyFactory factory;
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static void destroyPassword(char[] password) {
        if (password != null)
            Arrays.fill(password, ' ');
    }

    public static void destroyPasskey(byte[] passkey) {
        if (passkey != null)
            Arrays.fill(passkey, (byte) 0);
    }

}
