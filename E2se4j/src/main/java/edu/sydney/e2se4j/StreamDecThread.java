package edu.sydney.e2se4j;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class StreamDecThread extends Thread {
    private static List<InputStream> list;
    private final String sourceInterPath, desPath;
    private byte[] key;
    private int partNum;

    StreamDecThread(List<InputStream> decList, String sourceInterPath, String desPath, byte[] key, int partNum) {
        this.list = decList;
        this.sourceInterPath = sourceInterPath;
        this.desPath = desPath;
        this.key = key;
        this.partNum = partNum;
    }

    public void run() {
        try {
            decryptStreamCTRCombine(sourceInterPath, desPath, key, partNum);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }

    public static void decryptStreamCTRCombine(String sourceInterPath, String desPath, byte[] key, int partNum) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        int index = 0;
        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        try (FileOutputStream fileOutputStream = new FileOutputStream(desPath)) {
        }
        try (FileOutputStream fileOutputStream = new FileOutputStream(desPath, true)) {
            while (index < partNum) {
                index++;
                byte[] plainText;
                while (list.size() < index) ;
                try (InputStream input = list.get(index - 1)) {
                    int total = input.available();
                    byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
                    input.read(iv);
                    cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));
                    byte[] read_buf = new byte[1024];
                    int read_len = 0;
                    while ((read_len = input.read(read_buf)) > 0) {
                        byte[] dec = cipher.update(read_buf, 0, read_len);
                        fileOutputStream.write(dec);
                    }
                    byte[] dec = cipher.doFinal();
                    fileOutputStream.write(dec);
                }
            }
        }

    }
}
