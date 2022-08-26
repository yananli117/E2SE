package edu.sydney.e2se4j;

import org.bouncycastle.math.ec.ECPoint;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.time.StopWatch;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.s3.model.BucketAccelerateConfiguration;
import com.amazonaws.services.s3.model.BucketAccelerateStatus;
import com.amazonaws.services.s3.model.SetBucketAccelerateConfigurationRequest;
import com.amazonaws.services.s3.model.*;

public class Client {

    private SocketFactory socketFactory;
    private Logger logger;
    private int kdfHashRepetitions;
    private boolean useTLS;

    private final String accessKeyId;
    private final String secretKeyId;
    private final String regionName;
    public final String bucketName;

    /**
     * S3 credential configuration
     * @param accessKeyId: S3 credential
     * @param secretKeyId: S3 credential
     * @param regionName
     * @param bucketName
     */
    /*private static final String accessKeyId = "please enter the S3 credential access";
    private static final String secretKeyId = "please enter the S3 credential access";
    private static final String regionName = "ap-northeast-1";
    public static final String bucketName = "mybucket-tokyo2022";
*/
    private static final boolean verbose = false;

    private static final String internalCipherFilePath = Constants.FILE_PATH + "internal";
    private static final String plainFilePath = Constants.FILE_PATH + "plain";
    private static final String secureRetFilePath = Constants.FILE_PATH + "secureRetrieve";
    private static final String optSecureRetFilePath = Constants.FILE_PATH + "optSecureRetrieve";
    private static final String encryptionFilePath = Constants.FILE_PATH + "encryption";
    private static final String decryptionFilePath = Constants.FILE_PATH + "decryption";

    SimpleEcCurve curve = new SimpleEcCurve(Constants.CURVE_NAME);

    public Client setSocketFactory(SocketFactory socketFactory) {
        this.socketFactory = socketFactory;
        return this;
    }

    public Client setKdfHashRepetitions(int n) {
        this.kdfHashRepetitions = n;
        return this;
    }

    public Client setUseTLS(boolean b) {
        this.useTLS = b;
        return this;
    }

    public Client setLogger(Logger l) {
        this.logger = l;
        return this;
    }

    public interface Logger {
        void log(String tag, String message);

        void log(String message);
    }

    public Client(String accessKeyId, String secretKeyId, String regionName, String bucketName) {

        this(SSLSocketFactory.getDefault(), new Client.Logger(){

            @Override
            public void log(String message) {
                System.out.println(message);
            }
            @Override
            public void log(String tag, String message) {
                log(tag + ": " + message);
            }
        }, Constants.KDF_HASH_REPETITIONS, Constants.USE_TLS, accessKeyId, secretKeyId, regionName, bucketName);
    }


    public Client(SocketFactory socketFactory, Logger logger, int kdmHashRepetitions, boolean useTLS, String accessKeyId, String secretKeyId, String regionName, String bucketName) {
        this.socketFactory = socketFactory;
        this.logger = logger;
        this.kdfHashRepetitions = kdmHashRepetitions;
        this.useTLS = useTLS;
        this.accessKeyId = accessKeyId;
        this.secretKeyId = secretKeyId;
        this.regionName = regionName;

        //this.accessKeyId = accessKeyId;
        //this.secretKeyId = secretKeyId;
        //this.regionName = regionName;
        //this.bucketName = bucketName;

        this.bucketName = bucketName;
    }



    /**
     * one user start the client, only runs register give and take procedure, including IBOPRF
     * @throws Exception
     */
    public void startRGT() throws Exception {
        byte[] randomBytes = new byte[10];
        Random rand = new Random();
        rand.nextBytes(randomBytes);
        String userID = "username" + Utils.bytesToHex(randomBytes);
        rand.nextBytes(randomBytes);
        String passphrase = "passphrase" + Utils.bytesToHex(randomBytes);
        String key5 = "RGT"+userID + "/sid";
        String key6 = "RGT"+userID + "/rid";

        long giveTime, takeTime, oprfTime, oprfTime0, oprfTime1;
        byte[] msk, mskr;
        String hardenedPWD, hardenedPWD1;
        StopWatch stopWatch = new StopWatch();

        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        stopWatch.start();
        hardenedPWD = ibOPRF(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase);
        stopWatch.stop();
        oprfTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL time:" + oprfTime);

        register(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase, bucketName, key5);

        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        stopWatch.start();
        ibOPRF(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase);
        stopWatch.stop();
        oprfTime0 = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL time",  ""+oprfTime0);

        if (verbose) logger.log("KEY DEPOSIT PROTOCOL");
        stopWatch.start();
        msk = give(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase, bucketName, key6, key5);
        stopWatch.stop();
        giveTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("KEY DEPOSIT PROTOCOL time", ""+giveTime);

        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        stopWatch.start();
        hardenedPWD1 = ibOPRF(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase);
        stopWatch.stop();
        oprfTime1 = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL time", "" + oprfTime1);

        if (verbose) logger.log("KEY RETRIEVAL PROTOCOL");
        stopWatch.start();
        mskr = take(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase, bucketName, key6, key5);
        stopWatch.stop();
        takeTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Key Retrieval time =" + takeTime);
        if (!Arrays.equals(msk, mskr)) {
            throw new Exception("msk does not match");
        }

        System.out.println(oprfTime0 + "," + giveTime + "," + oprfTime1 + "," + takeTime);
        if (hardenedPWD1.equals(hardenedPWD)) ;
        else logger.log("The hardened password is " + hardenedPWD + "and " + hardenedPWD1);
    }

    /**
     * one user start the client and run the full procedure:
     *
     * @param sourceFilePath
     * @throws Exception
     * @including ibOPRF+register, ibOPRF+give, optimized secure deposit
     * @including ibOPRF+take, optimized secure retrieve
     */
    public void start(String sourceFilePath) throws Exception {

        byte[] randomBytes = new byte[10];
        Random rand = new Random();
        rand.nextBytes(randomBytes);
        String userID = "username" + Utils.bytesToHex(randomBytes);
        rand.nextBytes(randomBytes);
        String passphrase = "passphrase" + Utils.bytesToHex(randomBytes);
        String key0 = userID + "/sid";
        String key1 = userID + "/rid";
        String key2 = userID + "/optimizedEncryptedFile";
        String key3 = userID + "/plianFile";
        String key4 = userID + "/oneThreadEncryptedFile";
        long giveTime, takeTime, oprfTime, oprfTime0, oprfTime1;
        long encTime, decTime;
        long depPlainTime, retPlainTime, depEncTimeMultiThread, retDecTimeMultiThread, depEncTimeOneThread, retDecTimeOneThread;
        byte[] msk, mskr;
        int partNum;
        String hardenedPWD, hardenedPWD1;
        StopWatch stopWatch = new StopWatch();
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        stopWatch.start();
        hardenedPWD = ibOPRF(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase);
        stopWatch.stop();
        oprfTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL time", ""+ oprfTime);
/*
        register(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase, bucketName, key0);

        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        stopWatch.start();
        hardenedPWD = ibOPRF(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase);
        stopWatch.stop();
        oprfTime0 = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL time:" + oprfTime0);

        if (verbose) logger.log("KEY DEPOSIT PROTOCOL");
        stopWatch.start();
        msk = give(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase, bucketName, key1, key0);
        stopWatch.stop();
        giveTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("KEY DEPOSIT PROTOCOL time:" + giveTime);

        if (verbose) logger.log("ENCRYPT AND UPLOAD FILE");
        stopWatch.start();
        partNum = secureDepositOptimization(bucketName, key2, msk, sourceFilePath);
        stopWatch.stop();
        depEncTimeMultiThread = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Enc and upload file time = " + depEncTimeMultiThread);

        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        stopWatch.start();
        hardenedPWD1 = ibOPRF(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase);
        stopWatch.stop();
        oprfTime1 = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL time:" + oprfTime1);

        if (verbose) logger.log("KEY RETRIEVAL PROTOCOL\n");
        stopWatch.start();
        mskr = take(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER, Constants.AUTH_SERVER_NAME, userID, passphrase, bucketName, key1, key0);
        stopWatch.stop();
        takeTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Key Retrieval time =" + takeTime);
        if (!Arrays.equals(msk, mskr)) {
            throw new Exception("msk does not match");
        }

        if (verbose) logger.log("RETRIEVE AND DEC FILE");
        stopWatch.start();
        secureRetrieveOptimization(partNum, bucketName, key2, mskr, optSecureRetFilePath);
        stopWatch.stop();
        retDecTimeMultiThread = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Retrieve and dec time =" + retDecTimeMultiThread);

        if (verbose) logger.log("ENCRYPT AND UPLOAD FILE");
        stopWatch.start();
        secureDeposit(bucketName, key4, msk, sourceFilePath, internalCipherFilePath);
        stopWatch.stop();
        depEncTimeOneThread = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Enc and upload file time = " + depEncTimeOneThread);

        if (verbose) logger.log("RETRIEVE AND DEC FILE\n");
        stopWatch.start();
        secureRetrieve(bucketName, key4, mskr, secureRetFilePath);
        stopWatch.stop();
        retDecTimeOneThread = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Retrieve and dec time =" + retDecTimeOneThread);

        if (verbose) logger.log("UPLOAD PLAIN FILE\n");
        stopWatch.start();
        depositPlainFile(bucketName, key3, sourceFilePath);
        stopWatch.stop();
        depPlainTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Upload plain file time =" + depPlainTime);

        if (verbose) logger.log("RETRIEVE PLAIN FILE");
        stopWatch.start();
        retrievePlainBigFile(bucketName, key3, plainFilePath);
        stopWatch.stop();
        retPlainTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Retrieve plain file time =" + retPlainTime);

        if (verbose) logger.log("Encrypt PLAIN FILE");
        stopWatch.start();
        encryptCTRBigFile(sourceFilePath, encryptionFilePath, msk);
        stopWatch.stop();
        encTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Retrieve plain file time =" + encTime);

        if (verbose) logger.log("Decrypt CT FILE");
        stopWatch.start();
        decryptCTRBigFile(encryptionFilePath, decryptionFilePath, mskr);
        stopWatch.stop();
        decTime = stopWatch.getTime();
        stopWatch.reset();
        if (verbose) logger.log("Retrieve plain file time =" + decTime);

        System.out.println(oprfTime0 + "," + giveTime + "," + oprfTime1 + "," + takeTime + "," + depPlainTime + "," + retPlainTime + "," + depEncTimeMultiThread + "," + retDecTimeMultiThread + "," + depEncTimeOneThread + "," + retDecTimeOneThread + "," + encTime + "," + decTime + "," + partNum);
        if (hardenedPWD1.equals(hardenedPWD)) ;
        else logger.log("The hardened password is " + hardenedPWD + "and " + hardenedPWD1);
*/
        System.out.println(oprfTime);
    }

    /**
     * the subroutine connectAndGetSocket(): build socket connection with authserver
     *
     * @param address: of target server
     * @param port
     * @param name
     * @return socket
     * @throws Exception
     */
    public Socket connectAndGetSocket(String address, int port, String name) throws Exception {
        if (useTLS) {
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(address, port);
            socket.setEnabledProtocols(new String[]{Constants.TLS_VERSION});
            socket.setEnabledCipherSuites(new String[]{Constants.TLS_CIPHERSUITE});

            SSLSession s = socket.getSession();
            if (!s.getPeerPrincipal().getName().equals(name)) {
                throw new Exception("Hostname verification failed: " + s.getPeerPrincipal().getName() + "");
            }

            return socket;
        } else {
            return SocketFactory.getDefault().createSocket(address, port);
        }
    }


    /***IBOPRF protocol
     *
     * @param authServerAddress authserver
     * @param authServerPort authserver
     * @param authServerName authserver
     * @param userID user id
     * @param passphrase user password
     * @return the hardened password
     * @throws Exception
     */
    public String ibOPRF(String authServerAddress, int authServerPort, String authServerName, String userID, String passphrase) throws Exception {

        SecureRandom random = new SecureRandom();
        byte[] message = passphrase.getBytes(StandardCharsets.UTF_8);

        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        ECPoint hashPoint = curve.hash2Curve(message, hash);

        BigInteger k = curve.randomBigInteger(random);
        ECPoint blindPoint = hashPoint.multiply(k).normalize();
        byte[] blindPointBytes = blindPoint.getEncoded(true);

        Socket authServerSock = connectAndGetSocket(authServerAddress, authServerPort, authServerName);
        OutputStream out = authServerSock.getOutputStream();
        out.write(Constants.REQ_TYPE_AUTHSERVER_OPRF);
        out.write(userID.getBytes().length);
        out.write(userID.getBytes());

        out.write(blindPointBytes.length);
        out.write(blindPointBytes);

        InputStream in = authServerSock.getInputStream();
        byte depositAuthServerResponse = (byte) in.read();
        switch (depositAuthServerResponse) {
            case Constants.RESP_TYPE_OK:
                if (verbose) logger.log("Deposit protocol succeeded.");
                break;
            case Constants.RESP_TYPE_ERROR:
                throw new Exception("Auth Server error in Deposit Protocol!");
            default:
                throw new Exception("Auth Server error in Deposit Protocol!");
        }

        byte[] blindedecPointBytes = new byte[in.read()];
        in.read(blindedecPointBytes);
        ECPoint blindedecPoint = curve.ecDomainParameters.getCurve().decodePoint(blindedecPointBytes);

        BigInteger kInv = k.modInverse(curve.n);
        ECPoint bEcPointDerive = blindedecPoint.multiply(kInv).normalize();
        byte[] bEcPointDeriveByte = bEcPointDerive.getEncoded(true);
        BigInteger hardenedPWD = curve.hashToGroup2(bEcPointDeriveByte, passphrase.getBytes(StandardCharsets.UTF_8));

        authServerSock.close();

        return hardenedPWD.toString();
    }

    /***register protocol-register to auth server and data server
     *
     * @param authServerAddress
     * @param authServerPort
     * @param authServerName
     * @param userID
     * @param passphrase
     * @param bucketName: data server bucket name
     * @param key0: position for storing sid
     * @throws Exception
     * @callSubroutine createFileFromByte(): creat a file from bytes
     */
    public void register(String authServerAddress, int authServerPort, String authServerName, String userID, String passphrase, String bucketName, String key0) throws Exception {

        byte[] sid = new byte[Constants.R_LENGTH];
        Random rand = new Random();
        rand.nextBytes(sid);

        {
            try {
                BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
                final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).build();

                s3.putObject(new PutObjectRequest(bucketName, key0, createFileFromByte(sid)));

            } catch (AmazonServiceException ase) {
                System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
                System.out.println("Error Message:    " + ase.getMessage());
                System.out.println("HTTP Status Code: " + ase.getStatusCode());
                System.out.println("AWS Error Code:   " + ase.getErrorCode());
                System.out.println("Error Type:       " + ase.getErrorType());
                System.out.println("Request ID:       " + ase.getRequestId());
                throw ase;
            } catch (AmazonClientException ace) {
                System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
                System.out.println("Error Message: " + ace.getMessage());
                throw ace;
            }
        }
        byte[] t = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, kdfHashRepetitions);
        Socket authServerSock = connectAndGetSocket(authServerAddress, authServerPort, authServerName);

        OutputStream out = authServerSock.getOutputStream();

        out.write(Constants.REQ_TYPE_AUTHSERVER_REGISTER);
        out.write(userID.getBytes().length);
        out.write(userID.getBytes());

        out.write(t.length);
        out.write(t);
        InputStream in = authServerSock.getInputStream();
        byte depositAuthServerResponse = (byte) in.read();
        switch (depositAuthServerResponse) {
            case Constants.RESP_TYPE_OK:
                if (verbose) logger.log("Register protocol succeeded.");
                break;
            case Constants.RESP_TYPE_ERROR:
                throw new Exception("Auth Server error in Register Protocol!");
            default:
                throw new Exception("Auth Server error in Register Protocol!");
        }

        authServerSock.close();

    }

    /***give protocol-deposit secret to auth server and data server
     * @param authServerAddress
     * @param authServerPort
     * @param authServerName
     * @param userID
     * @param passphrase
     * @param bucketName
     * @param key1: index of storing rid
     * @param key0: index of storing sid
     * @return data encryption key for verification, can be void
     * @throws Exception
     * @callSubroutine createFileFromByte(): create a file for bytes
     */
    public byte[] give(String authServerAddress, int authServerPort, String authServerName, String userID, String passphrase, String bucketName, String key1, String key0) throws Exception {

        long time1 = System.currentTimeMillis();
        Socket authServerSock = connectAndGetSocket(authServerAddress, authServerPort, authServerName);
        long time2 = System.currentTimeMillis();

        byte[] rid = new byte[Constants.R_LENGTH];
        byte[] sid = new byte[Constants.R_LENGTH];
        Random rand = new Random();
        rand.nextBytes(rid);
        byte[] parameter = new byte[Constants.R_LENGTH];
        System.arraycopy(rid, 0, parameter, 0, Constants.R_LENGTH);

        {
            try {
                BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
                final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).build();

                s3.putObject(new PutObjectRequest(bucketName, key1, createFileFromByte(parameter)));

                S3Object object = s3.getObject(new GetObjectRequest(bucketName, key0));
                sid = IOUtils.toByteArray(object.getObjectContent());


            } catch (AmazonServiceException ase) {
                System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
                System.out.println("Error Message:    " + ase.getMessage());
                System.out.println("HTTP Status Code: " + ase.getStatusCode());
                System.out.println("AWS Error Code:   " + ase.getErrorCode());
                System.out.println("Error Type:       " + ase.getErrorType());
                System.out.println("Request ID:       " + ase.getRequestId());
                throw ase;
            } catch (AmazonClientException ace) {
                System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
                System.out.println("Error Message: " + ace.getMessage());
                throw ace;
            }
        }

        long time7 = System.currentTimeMillis();
        KeyGenerator kgen = KeyGenerator.getInstance(Constants.DATA_ENCRYPTION_BASE_ALGORITHM);
        byte[] msk = kgen.generateKey().getEncoded();

        if (verbose) logger.log("Generated msk: " + Utils.bytesToHex(msk));

        byte[] t = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, kdfHashRepetitions);
        byte[] k1 = Utils.KDF(rid, passphrase, Constants.KDF2_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);
        byte[] k2 = Utils.KDF(rid, passphrase, Constants.KDF3_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);

        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(k1, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey);
        byte[] ct = cipher.doFinal(msk);
        byte[] iv = cipher.getIV();

        ByteArrayOutputStream ivCt = new ByteArrayOutputStream();
        ivCt.write(iv);
        ivCt.write(ct);
        byte[] ivct = ivCt.toByteArray();
        byte[] tao = Utils.KDF(ivct, Arrays.toString(k2), Constants.KDF4_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);

        long time3 = System.currentTimeMillis();
        OutputStream out = authServerSock.getOutputStream();
        out.write(Constants.REQ_TYPE_AUTHSERVER_DEPOSIT);
        out.write(userID.getBytes().length);
        out.write(userID.getBytes());
        out.write(t.length);
        out.write(t);
        out.write(tao.length);
        out.write(tao);
        out.write(ivct.length);
        out.write(ivct);

        InputStream in = authServerSock.getInputStream();
        byte depositAuthServerResponse = (byte) in.read();
        switch (depositAuthServerResponse) {
            case Constants.RESP_TYPE_OK:
                if (verbose) logger.log("Deposit protocol succeeded.");
                break;
            case Constants.RESP_TYPE_ERROR:
                throw new Exception("Auth Server error in Deposit Protocol!");
            default:
                throw new Exception("Auth Server error in Deposit Protocol!");
        }

        authServerSock.close();
        return msk;
    }

    /***take protocol: retreive data encryption key from auth server and data server
     *
     * @param authServerAddress
     * @param authServerPort
     * @param authServerName
     * @param userID
     * @param passphrase
     * @param bucketName
     * @param key1
     * @param key0
     * @return mskr: data encryption key
     * @throws Exception
     * @throws IOException
     * @callSubroutine connectAndGetSocket(): build connection with authserver
     */
    public byte[] take(String authServerAddress, int authServerPort, String authServerName, String userID, String passphrase, String bucketName, String key1, String key0) throws Exception, IOException {
        BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
        if (verbose) {
            logger.log("Uploading  to S3 bucket %s...\n", bucketName);
        }
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).build();
        byte[] sid = new byte[Constants.R_LENGTH];
        byte[] rid = new byte[Constants.R_LENGTH];
        try {

            if (verbose) System.out.println("Retrive parameter\n");
            S3Object object = s3.getObject(new GetObjectRequest(bucketName, key1));

            byte[] encryptedData = IOUtils.toByteArray(object.getObjectContent());
            rid = Arrays.copyOfRange(encryptedData, 0, Constants.R_LENGTH);
            S3Object object2 = s3.getObject(new GetObjectRequest(bucketName, key0));
            sid = IOUtils.toByteArray(object2.getObjectContent());
        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            throw ase;
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            throw ace;
        }
        byte[] t = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, kdfHashRepetitions);
        byte[] k1 = Utils.KDF(rid, passphrase, Constants.KDF2_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);
        byte[] k2 = Utils.KDF(rid, passphrase, Constants.KDF3_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);


        Socket authServerSock = connectAndGetSocket(authServerAddress, authServerPort, authServerName);
        OutputStream out = authServerSock.getOutputStream();

        out.write(Constants.REQ_TYPE_AUTHSERVER_RETRIEVAL);
        out.write(userID.getBytes().length);
        out.write(userID.getBytes());
        out.write(t);

        InputStream in = authServerSock.getInputStream();
        byte retrievalAuthServerResponse = (byte) in.read();
        switch (retrievalAuthServerResponse) {
            case Constants.RESP_TYPE_OK:
                if (verbose) logger.log("Retrieval protocol succeeded.");
                break;
            case Constants.RESP_TYPE_ERROR:
                logger.log("Retrieval failed! (Auth Server returned error)");
                throw new Exception("Auth Server error in Retrieval Protocol!");
                // break;
            default:
                logger.log("Received unexpected response from server.");
                throw new Exception("Auth Server error in Retrieval Protocol!");
        }

        byte[] ct = new byte[in.read() - Constants.KEY_ENCRYPTION_IV_LENGTH];
        byte[] iv = new byte[Constants.KEY_ENCRYPTION_IV_LENGTH];
        in.read(iv);
        in.read(ct);
        byte[] tao = new byte[in.read()];
        in.read(tao);
        ByteArrayOutputStream ivCt = new ByteArrayOutputStream();
        ivCt.write(iv);
        ivCt.write(ct);
        byte[] ivct = ivCt.toByteArray();

        byte[] taoCal = Utils.KDF(ivct, Arrays.toString(k2), Constants.KDF4_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);
        if (!Arrays.equals(tao, taoCal)) {
            logger.log("User " + userID + " did not take a valid tao. Retrieval request ignored.");
        }

        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(k1, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new GCMParameterSpec(Constants.GCM_TAG_LENGTH, iv));
        byte[] mskr = cipher.doFinal(ct);


        authServerSock.close();
        return mskr;

    }

    /***deposit plain file
     *
     * @param bucketName
     * @param key3: index of storing plain file
     * @param sourceFilePath: plain file path
     */
    public void depositPlainFile(String bucketName, String key3, String sourceFilePath) {
        try {
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
            final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).enableAccelerateMode().build();

            s3.setBucketAccelerateConfiguration(new SetBucketAccelerateConfigurationRequest(bucketName, new BucketAccelerateConfiguration(BucketAccelerateStatus.Enabled)));


            s3.putObject(new PutObjectRequest(bucketName, key3, new File(sourceFilePath)));
        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            throw ase;
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            throw ace;
        }
    }


    /***retrieve plain big file
     * @param bucketName
     * @param key3: index of storing plain file
     * @param plainFilePath: destination path
     * @throws IOException
     */
    public void retrievePlainBigFile(String bucketName, String key3, String plainFilePath) throws IOException {
        try {
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
            final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).enableAccelerateMode().build();

            s3.setBucketAccelerateConfiguration(new SetBucketAccelerateConfigurationRequest(bucketName, new BucketAccelerateConfiguration(BucketAccelerateStatus.Enabled)));

            S3Object object = s3.getObject(new GetObjectRequest(bucketName, key3));
            S3ObjectInputStream s3is = object.getObjectContent();
            FileOutputStream fos = new FileOutputStream(plainFilePath);
            byte[] read_buf = new byte[1024];
            int read_len = 0;
            while ((read_len = s3is.read(read_buf)) != -1) {
                fos.write(read_buf, 0, read_len);
            }
            s3is.close();
            fos.close();
        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            throw ase;
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            throw ace;
        } catch (FileNotFoundException afe) {
            System.err.println(afe.getMessage());
            throw afe;
        } catch (IOException aie) {
            System.err.println(aie.getMessage());
            System.exit(1);
        }
    }


    /***secure deposit with one thread : read file from disk + enc+ write file to disk +  deposit
     * @note: return Enc time, not shown in the test
     * @param bucketName
     * @param key2: index of storing one-thread ct file
     * @param sKey
     * @param sourceFilePath
     * @param internalCipherFilePath
     * @return enctime
     * @throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException
     * @throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException
     */
    public long secureDepositReturnEncTime(String bucketName, String key2, byte[] sKey, String sourceFilePath, String internalCipherFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        long start = 0, end = 0;
        start = System.currentTimeMillis();
        encryptCTRBigFile(sourceFilePath, internalCipherFilePath, sKey);

        end = System.currentTimeMillis();
        long EncTime = end - start;
        try {
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
            final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).enableAccelerateMode().build();

            s3.setBucketAccelerateConfiguration(new SetBucketAccelerateConfigurationRequest(bucketName, new BucketAccelerateConfiguration(BucketAccelerateStatus.Enabled)));

            s3.putObject(new PutObjectRequest(bucketName, key2, new File(internalCipherFilePath)));
            long elapsed = System.currentTimeMillis();
            long UploadEncTime = elapsed - start;
        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            throw ase;
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            throw ace;
        }
        return EncTime;
    }

    /***secure deposit in one thread: read file from disk + enc+ write file to disk
     * @note function same as secureDepositReturnEncTime()
     * @param bucketName
     * @param key2
     * @param sKey
     * @param sourceFilePath
     * @param internalCipherFilePath
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeySpecException
     */
    public void secureDeposit(String bucketName, String key2, byte[] sKey, String sourceFilePath, String internalCipherFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        try {
            long start = System.currentTimeMillis();
            encryptCTRBigFile(sourceFilePath, internalCipherFilePath, sKey);

            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
            final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).enableAccelerateMode().build();

            // Enable Transfer Acceleration for the specified bucket.
            s3.setBucketAccelerateConfiguration(new SetBucketAccelerateConfigurationRequest(bucketName, new BucketAccelerateConfiguration(BucketAccelerateStatus.Enabled)));

            s3.putObject(new PutObjectRequest(bucketName, key2, new File(internalCipherFilePath)));
            long elapsed = System.currentTimeMillis();
            long UploadEncTime = elapsed - start;
        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            throw ase;
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            throw ace;
        }
    }

    /***the subroutine for enc a big file with CTR mode
     * @note: test encryption time: read plain file from disk + encrypt + write ct to the disk
     * @param sourcePath: plain file path
     * @param desPath: destination ct file path
     * @param key: data encryption key
     * @throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException
     * @throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException
     */
    public static void encryptCTRBigFile(String sourcePath, String desPath, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        try {
            Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
            SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, ivParameterSpec);

            byte[] buffer = new byte[1024 * 1024];
            InputStream in = new FileInputStream(sourcePath);

            OutputStream out = new FileOutputStream(desPath);

            int index;
            out.write(iv);
            while ((index = in.read(buffer)) != -1) {
                byte[] enc = cipher.update(buffer, 0, index);
                out.write(enc);
            }
            byte[] enc = cipher.doFinal();
            out.write(enc);
            in.close();
            out.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /***secure retrieve with one thread: retrieve ct from S3 + decrypt ct + write to disk
     * @note function same as secureRetrieveReturnDecTime()
     * @param bucketName
     * @param key2
     * @param sKey
     * @param desPath
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public void secureRetrieve(String bucketName, String key2, byte[] sKey, String desPath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (verbose) {
            System.out.format("Retrieving from S3 bucket %s...\n", bucketName);
        }
        try {
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
            final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).enableAccelerateMode().build();

            // Enable Transfer Acceleration for the specified bucket.
            s3.setBucketAccelerateConfiguration(new SetBucketAccelerateConfigurationRequest(bucketName, new BucketAccelerateConfiguration(BucketAccelerateStatus.Enabled)));

            if (verbose) {
                System.out.println("Retrive File from bucket " + bucketName);
                System.out.println("Retrive parameter\n");
            }

            long start1 = System.currentTimeMillis();
            S3Object object = s3.getObject(new GetObjectRequest(bucketName, key2));
            S3ObjectInputStream s3is = object.getObjectContent();
            FileOutputStream fos = new FileOutputStream(desPath);

            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            s3is.read(iv);
            Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
            SecretKey keyEncryptionKey = new SecretKeySpec(sKey, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

            int index;
            byte[] buffer = new byte[1024];
            while ((index = s3is.read(buffer)) != -1) {
                byte[] dec = cipher.update(buffer, 0, index);
                fos.write(dec);
            }
            byte[] dec = cipher.doFinal();
            fos.write(dec);
            s3is.close();
            fos.close();

            long elapsed1 = System.currentTimeMillis();
            if (verbose) System.out.println("\nDownload and Dec File time = " + (elapsed1 - start1));

        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            throw ase;
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            throw ace;
        } catch (FileNotFoundException afe) {
            System.err.println(afe.getMessage());
            System.exit(1);
        } catch (IOException aie) {
            System.err.println(aie.getMessage());
            System.exit(1);
        }
    }

    /***secure retrieve with one thread: retrieve ct from S3 + decrypt ct + write to disk
     * @note: return the decryption time: decrypt + write to the disk, not used in the test
     * @param bucketName
     * @param key2
     * @param sKey
     * @param desPath
     * @param internalCipherFilePath
     * @return Dec time: decrypt stream from S3 + write to disk
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public long secureRetrieveReturnDecTime(String bucketName, String key2, byte[] sKey, String desPath, String internalCipherFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        if (verbose) {
            System.out.format("Retrieving from S3 bucket %s...\n", bucketName);
        }
        long start = 0, end = 0;
        try {
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
            final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).enableAccelerateMode().build();

            // Enable Transfer Acceleration for the specified bucket.
            s3.setBucketAccelerateConfiguration(new SetBucketAccelerateConfigurationRequest(bucketName, new BucketAccelerateConfiguration(BucketAccelerateStatus.Enabled)));

            if (verbose) {
                System.out.println("Retrive File from bucket " + bucketName);
                System.out.println("Retrive parameter\n");
            }

            long start1 = System.currentTimeMillis();
            S3Object object = s3.getObject(new GetObjectRequest(bucketName, key2));
            S3ObjectInputStream s3is = object.getObjectContent();

            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            s3is.read(iv);
            Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
            SecretKey keyEncryptionKey = new SecretKeySpec(sKey, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

            FileOutputStream fos = new FileOutputStream(desPath);
            int index;
            byte[] buffer = new byte[1024];
            start = System.currentTimeMillis();
            while ((index = s3is.read(buffer)) != -1) {
                byte[] dec = cipher.update(buffer, 0, index);
                fos.write(dec);
            }
            byte[] dec = cipher.doFinal();
            fos.write(dec);
            end = System.currentTimeMillis();

            s3is.close();
            fos.close();

            long elapsed1 = System.currentTimeMillis();
            if (verbose) System.out.println("\nDownload and Dec File time = " + (elapsed1 - start1));

        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            throw ase;
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            throw ace;
        } catch (FileNotFoundException afe) {
            System.err.println(afe.getMessage());
            System.exit(1);
        } catch (IOException aie) {
            System.err.println(aie.getMessage());
            System.exit(1);
        }
        return end - start;
    }


    /***optimization: for encrypting file + uploading ct
     * @param bucketName
     * @param key2
     * @param sKey
     * @param sourceFilePath
     * @return split number
     * @throws NoSuchPaddingException, IOException, NoSuchAlgorithmException,  InvalidAlgorithmParameterException
     * @throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException
     * @callSubroutine EncThread()
     * @callSubroutine uploadFilePartsToS3()
     */
    public int secureDepositOptimization(String bucketName, String key2, byte[] sKey, String sourceFilePath) throws NoSuchPaddingException, IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        int partSize;
        int partNumber;

        long start1 = System.currentTimeMillis();
        try (FileInputStream fileInputStream = new FileInputStream(sourceFilePath)) {
            double fileSize = fileInputStream.available();
            double sqrtSize = Math.sqrt(fileSize / 1024 / 1024 / 20.0);
            if (sqrtSize > 0 && sqrtSize <= 1) partNumber = 1;
            else partNumber = (int) Math.round(sqrtSize);
            partSize = (int) Math.ceil(((double) fileSize) / partNumber);
        }
        long elapsed1 = System.currentTimeMillis();

        List<Integer> encList = new CopyOnWriteArrayList<Integer>();
        Thread threadEnc = new EncThread(encList, partNumber, partSize, sourceFilePath, internalCipherFilePath, sKey);
        threadEnc.start();

        uploadFilePartsToS3(encList, partNumber, internalCipherFilePath, bucketName, key2);
        try {
            threadEnc.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return partNumber;
    }

    /***the subroutine uploadFilePartsToS3() of optimization: deposit ct by parts
     * @param list
     * @param partNum
     * @param filePath
     * @param bucketName
     * @param key2
     * @throws IOException
     */
    public void uploadFilePartsToS3(List<Integer> list, int partNum, String filePath, String bucketName, String key2) throws IOException {
        BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);

        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).enableAccelerateMode().build();
        // Enable Transfer Acceleration for the specified bucket.
        s3.setBucketAccelerateConfiguration(new SetBucketAccelerateConfigurationRequest(bucketName, new BucketAccelerateConfiguration(BucketAccelerateStatus.Enabled)));
        int index = 0;
        while (index < partNum) {
            index++;
            while (list.size() < index) ;
            try (InputStream inputStream = new FileInputStream(filePath + "EncPart" + index)) {
                int streamSize = inputStream.available();
                ObjectMetadata metadata = new ObjectMetadata();
                metadata.setContentLength(streamSize);
                String key2_part = key2 + "/part" + index;

                s3.putObject(new PutObjectRequest(bucketName, key2_part, inputStream, metadata));
            }
        }
    }

    /***optimization2: retrieve ct + dec ct in two threads
     *
     * @param partNum: split number
     * @param bucketName
     * @param key2 : index of storing secure optimized deposit
     * @param sKey : data encryption key
     * @param desPath
     * @throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException
     * @throws BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException
     * @callSubroutine StreamDecThread()
     */
    public void secureRetrieveOptimization(int partNum, String bucketName, String key2, byte[] sKey, String desPath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        List<InputStream> decList = new CopyOnWriteArrayList<>();
        if (verbose) {
            System.out.format("Retrieving from S3 bucket %s...\n", bucketName);
        }
        try {
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKeyId, secretKeyId);
            final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(regionName).withCredentials(new AWSStaticCredentialsProvider(awsCreds)).enableAccelerateMode().build();

            // Enable Transfer Acceleration for the specified bucket.
            s3.setBucketAccelerateConfiguration(new SetBucketAccelerateConfigurationRequest(bucketName, new BucketAccelerateConfiguration(BucketAccelerateStatus.Enabled)));

            long start1 = System.currentTimeMillis();
            Thread decThread = new StreamDecThread(decList, internalCipherFilePath, desPath, sKey, partNum);
            decThread.start();
            int index = 0;
            S3ObjectInputStream[] s3isset = new S3ObjectInputStream[partNum];
            while (index < partNum) {
                index++;
                String partKey = key2 + "/part" + index;
                S3Object object = s3.getObject(new GetObjectRequest(bucketName, partKey));

                s3isset[index - 1] = object.getObjectContent();
                decList.add(s3isset[index - 1]);

            }
            try {
                decThread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            for (int i = 0; i < partNum; i++) {
                s3isset[i].close();
            }

            long elapsed1 = System.currentTimeMillis();
            if (verbose) System.out.println("\nDownload and Dec File time = " + (elapsed1 - start1));

        } catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which means your request made it " + "to Amazon S3, but was rejected with an error response for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
            throw ase;
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which means the client encountered " + "a serious internal problem while trying to communicate with S3, " + "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
            throw ace;
        }
    }

    /***subroutine createFileFromByte(): return file on input  bytes
     *
     * @param input: bytes
     * @return File
     * @throws IOException
     */
    private static File createFileFromByte(byte[] input) throws IOException {
        File file = File.createTempFile("aws-java-sdk-", ".txt", null);
        file.deleteOnExit();

        try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            fileOutputStream.write(input);
        }
        return file;
    }

    /***the subroutine decryptCTRBigFile(): read ct file from disk + decrypt + write plain file to the disk
     * @note: used to test decryption time
     * @param sourcePath: path of ct file
     * @param desPath: path of destination plain file
     * @param key: data encryption key
     * @throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException
     * @throws BadPaddingException,  IllegalBlockSizeException, InvalidKeySpecException, IOException
     */
    public static void decryptCTRBigFile(String sourcePath, String desPath, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        byte[] buffer = new byte[1024 * 1024];
        InputStream in = new FileInputStream(sourcePath);
        OutputStream out = new FileOutputStream(desPath);
        byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
        in.read(iv);

        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

        int index;
        while ((index = in.read(buffer)) != -1) {
            byte[] dec = cipher.update(buffer, 0, index);
            out.write(dec);
        }
        byte[] dec = cipher.doFinal();
        out.write(dec);
        in.close();
        out.close();
    }

}
