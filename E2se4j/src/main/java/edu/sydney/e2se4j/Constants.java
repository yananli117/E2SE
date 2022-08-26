package edu.sydney.e2se4j;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Constants {
    public static final boolean USE_TLS = true;
    public static final int PWD_HASH_REPETITIONS = 1;
    public static final int KDF_HASH_REPETITIONS = 1;

    public static final String TLS_VERSION = "TLSv1.2";
    public static final String TLS_CIPHERSUITE = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

    public static final String ANDROID_LOCALHOST = "10.0.2.2";

    public static final byte REQ_TYPE_AUTHSERVER_DEPOSIT = 0x02;
    public static final byte REQ_TYPE_AUTHSERVER_RETRIEVAL = 0x03;
    public static final byte REQ_TYPE_AUTHSERVER_OPRF = 0x08;
    public static final byte REQ_TYPE_AUTHSERVER_REGISTER = 0x09;

    public static final byte RESP_TYPE_OK = 0x06;
    public static final byte RESP_TYPE_ERROR = 0x07;

    public static final int MAC_LENGTH = 32;
    public static final int MAC_KEY_LENGTH = 128;
    public static final int R_LENGTH = 128 / 8; // bytes
    public static final int HASHED_PASSWORD_LENGTH = 128; // bits
    public static final int ENC_KEY_LENGTH = 128;
    public static final int CHALLENGE_LENGTH = 128 / 8;

    public static final byte[] PASSWORD_SALT = (new String("edu.sydney.e2se.PASSWORD_SALT")).getBytes();
    public static final byte[] KDF1_SALT = (new String("edu.sydney.e2se.KDF1_SALT")).getBytes();
    public static final byte[] KDF2_SALT = (new String("edu.sydney.e2se.KDF2_SALT")).getBytes();
    public static final byte[] KDF3_SALT = (new String("edu.sydney.e2se.KDF3_SALT")).getBytes();
    public static final byte[] KDF4_SALT = (new String("edu.sydney.e2se.KDF4_SALT")).getBytes();

    public static final int MAX_FAILED_ATTEMPTS_DATASERVER = 3;
    public static final int MAX_FAILED_ATTEMPTS_AUTHSERVER = 3;

    public static final String MAC_ALGORITHM = "HMACSHA256";
    public static final String DATA_ENCRYPTION_BASE_ALGORITHM = "AES";
    public static final String KEY_ENCRYPTION_BASE_ALGORITHM = "AES";
    public static final String KEY_ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding"; // Algorithm used to encrypt msk
    public static final int KEY_ENCRYPTION_IV_LENGTH = 96 / 8; // bytes
    public static final int GCM_TAG_LENGTH = 16 * 8;

    public static final String KEY_ENCRYPTION_CTR_ALGORITHM = "AES/CTR/NoPadding";
    public static final int KEY_ENCRYPTION_CTR_IV_LENGTH = 128 / 8; // bytes

    public static final String CLIENT = "client";
    public static final String AUTH_SERVER = "authserver";

    public static final String FILE_PATH = "./DataFile/";
    public static final String AUTH_SERVER_KEYSTORE_PATH = "./certificatesNew/AuthServerKeyStore.jks";
    public static final String AUTH_SERVER_KEYSTORE_PASSWORD = "changeit";
    public static final String CURVE_NAME = "secp256r1";


//    public static final int AUTH_SERVER_PORT_NUMBER = 20202;
//    public static final String AUTH_SERVER_ADDRESS = "localhost";//"13.208.251.87";//ip
//    public static final String AUTH_SERVER_NAME = "CN=usyd.authserver,OU=authserver,O=server,L=sydney,ST=NSW,C=AU";

    public static final String AUTH_SERVER_ADDRESS = setIP();
    public static final int AUTH_SERVER_PORT_NUMBER = setPort();
    public static final String AUTH_SERVER_NAME = setName();
    static String setIP(){
        Properties prop = new Properties();
        InputStream input = null;
        String authServerIp = null;
        //String authServerPort = null;
        //String regionName = null;
        //String bucketName = null;

        try {

            input = new FileInputStream("config.properties");
            prop.load(input);
            authServerIp = prop.getProperty("authServerIp");
            //System.out.println(authServerIp);
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return authServerIp;
    }
    static int setPort(){
        Properties prop = new Properties();
        InputStream input = null;
        String authServerPort = null;

        try {

            input = new FileInputStream("config.properties");
            prop.load(input);
            authServerPort = prop.getProperty("authServerPort");
            //System.out.println(authServerPort);

        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return Integer.parseInt(authServerPort);
    }

    static String setName(){
        Properties prop = new Properties();
        InputStream input = null;
        String authServerName = null;
        //String authServerPort = null;
        //String regionName = null;
        //String bucketName = null;

        try {

            input = new FileInputStream("config.properties");
            prop.load(input);
            authServerName = prop.getProperty("authServerName");
            //System.out.println(authServerIp);
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return authServerName;
    }
}
