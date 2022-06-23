package edu.sydney.e2se4j;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class EncThread extends Thread {
    private final int partNum, partSiz;
    private final String souPath, desPath;
    private final byte[] key;
    private final List<Integer> list;


    EncThread(List<Integer> list, int partNum, int partSiz, String souPath, String desPath, byte[] key) {
        this.list = list;
        this.partNum = partNum;
        this.partSiz = partSiz;
        this.souPath = souPath;
        this.desPath = desPath;
        this.key = key;
    }

    public void run() {
        try {
            encryptFileToPartsOneSet(partNum, partSiz, souPath, desPath, key);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public void encryptFileToPartsOneSet(int partNum, int partSiz, String souPath, String desPath, byte[] key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        byte[] partBytes = new byte[partSiz];

        int index = 0;
        while (index < partNum - 1) {
            try (InputStream inp = new FileInputStream(souPath)) {
                inp.skip(index * partSiz);
                inp.read(partBytes);
            }

            index++;
            secureRandom.nextBytes(iv);
            IvParameterSpec parameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, parameterSpec);
            try (FileOutputStream fileOutputStream = new FileOutputStream(desPath + "EncPart" + index)) {
                byte[] ct = cipher.doFinal(partBytes);
                int totalLen = iv.length + ct.length;

                fileOutputStream.write(iv);
                fileOutputStream.write(ct);

            }
            list.add(index);
        }
        {
            index = partNum;
            int lenRead;
            try (InputStream inp = new FileInputStream(souPath)) {
                inp.skip((index - 1) * partSiz);
                lenRead = inp.read(partBytes);
            }

            secureRandom.nextBytes(iv);
            IvParameterSpec parameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, parameterSpec);

            try (FileOutputStream fileOutputStream = new FileOutputStream(desPath + "EncPart" + index)) {
                if (lenRead < partSiz) {
                    byte[] partShortBytes = Arrays.copyOfRange(partBytes, 0, lenRead);
                    byte[] ct = cipher.doFinal(partShortBytes);
                    int totalLen = iv.length + ct.length;

                    fileOutputStream.write(iv);
                    fileOutputStream.write(ct);
                } else {
                    byte[] ct = cipher.doFinal(partBytes);
                    int totalLen = iv.length + ct.length;

                    fileOutputStream.write(iv);
                    fileOutputStream.write(ct);
                }
            }
            list.add(index);
        }
    }
}
