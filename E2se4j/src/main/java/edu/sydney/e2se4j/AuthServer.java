package edu.sydney.e2se4j;

import org.bouncycastle.math.ec.ECPoint;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class AuthServer {
    private static final boolean verbose = false;

    final private static SimpleEcCurve SIMPLE_EC_CURVE = new SimpleEcCurve(Constants.CURVE_NAME);
    final private static String mSecretKey = "addd";

    class UserRecord {
        byte[] tao, ct;
        int c;

        public UserRecord(byte[] tao, byte[] ct) {
            this.tao = tao;
            this.ct = ct;
            this.c = 0;
        }
    }

    class UserRegister {
        byte[] t;
        int c;

        public UserRegister(byte[] t) {
            this.t = t;
            this.c = 0;
        }
    }

    public AuthServer() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println("TLS enabled: " + Constants.USE_TLS + ", PBKDF KDF iterations: " + Constants.KDF_HASH_REPETITIONS + ", PBKDF pwd hash iterations: " + Constants.PWD_HASH_REPETITIONS);

        AuthServer server = new AuthServer();
        server.start();
    }

    public void start() throws Exception {

        String msg = "AuthServer starting on port " + Constants.AUTH_SERVER_PORT_NUMBER + "...";
        System.out.println(msg);

        Map<String, UserRecord> usersRec = new HashMap<String, UserRecord>();
        Map<String, UserRegister> usersReg = new HashMap<String, UserRegister>();
        ServerSocket serverListener;

        if (Constants.USE_TLS) {

            System.setProperty("javax.net.ssl.keyStore", Constants.AUTH_SERVER_KEYSTORE_PATH);
            System.setProperty("javax.net.ssl.keyStorePassword", Constants.AUTH_SERVER_KEYSTORE_PASSWORD);

            serverListener = SSLServerSocketFactory.getDefault().createServerSocket(Constants.AUTH_SERVER_PORT_NUMBER);

            ((SSLServerSocket) serverListener).setEnabledProtocols(new String[]{Constants.TLS_VERSION});

            ((SSLServerSocket) serverListener).setEnabledCipherSuites(new String[]{Constants.TLS_CIPHERSUITE});

        } else {
            System.out.println("Is building an insecure http connection.");
            serverListener = new ServerSocket(Constants.AUTH_SERVER_PORT_NUMBER);
        }

        try {
            while (true) {
                Socket clientSocket = serverListener.accept();

                if (verbose) System.out.println("Client connected.");

                InputStream in = clientSocket.getInputStream();
                byte requestType = (byte) in.read();

                int useridLength = in.read();
                byte[] userIDBytes = new byte[useridLength];
                in.read(userIDBytes);
                String userID = new String(userIDBytes);

                switch (requestType) {
                    case Constants.REQ_TYPE_AUTHSERVER_OPRF: {
                        if (verbose) System.out.println("Received a OPRF Request.");

                        byte[] ecPBytes = new byte[in.read()];
                        in.read(ecPBytes);

                        long start = 0, end = 0;
                        start = System.currentTimeMillis();

                        ECPoint ecPoint = SIMPLE_EC_CURVE.ecDomainParameters.getCurve().decodePoint(ecPBytes);
                        BigInteger keyId = SIMPLE_EC_CURVE.hashToGroup2(mSecretKey.getBytes(StandardCharsets.UTF_8), userIDBytes);
                        ECPoint bEcPoint = ecPoint.multiply(keyId).normalize();
                        byte[] bytebEcPiont = bEcPoint.getEncoded(true);

                        end = System.currentTimeMillis();
                        long prfTime = end - start;
                        System.out.println(prfTime);
                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);
                        clientSocket.getOutputStream().write(bytebEcPiont.length);
                        clientSocket.getOutputStream().write(bytebEcPiont);
                        if (verbose) System.out.println("OPRF derivition request for " + userID + "succeeded.");

                    }
                    break;
                    case Constants.REQ_TYPE_AUTHSERVER_REGISTER: {
                        if (verbose) System.out.println("Received a Register Request.");

                        byte[] t = new byte[in.read()];
                        in.read(t);

                        if (usersReg.containsKey(userID)) {
                            System.out.println("User " + userID + " already registered. Register request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        usersReg.put(userID, new UserRegister(t));
                        if (verbose) System.out.println("Register for " + userID + " succeeded.");
                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);

                    }
                    break;
                    case Constants.REQ_TYPE_AUTHSERVER_DEPOSIT: {
                        if (verbose) System.out.println("Received a Deposit Request.");

                        if (!usersReg.containsKey(userID)) {
                            System.out.println("User " + userID + " did not register. Retrieval request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        if (usersRec.containsKey(userID)) {
                            System.out.println("User " + userID + " already deposited. Deposit request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        byte[] tReceive = new byte[in.read()];
                        in.read(tReceive);

                        UserRegister userR = usersReg.get(userID);
                        if (!Arrays.equals(userR.t, tReceive)) {
                            System.out.println("User " + userID + " did not enter a valid password. Deposit request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }


                        byte[] tao = new byte[in.read()];
                        in.read(tao);

                        byte[] ct = new byte[in.read()];
                        in.read(ct);

                        usersRec.put(userID, new UserRecord(tao, ct));
                        if (verbose) System.out.println("Deposit for " + userID + " succeeded.");
                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);

                    }
                    break;
                    case Constants.REQ_TYPE_AUTHSERVER_RETRIEVAL: {
                        if (verbose) System.out.println("Received a Retrieval Request.");

                        byte[] tReceive = new byte[Constants.R_LENGTH];
                        in.read(tReceive);

                        if (!usersReg.containsKey(userID)) {
                            System.out.println("User " + userID + " did not register. Retrieval request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        if (!usersRec.containsKey(userID)) {
                            System.out.println("User " + userID + " did not deposit a key. Retrieval request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }

                        UserRegister userR = usersReg.get(userID);

                        if (!Arrays.equals(userR.t, tReceive)) {
                            System.out.println("User " + userID + " did not enter a correct password. Retrieval request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }

                        UserRecord userC = usersRec.get(userID);


                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);
                        clientSocket.getOutputStream().write(userC.ct.length);
                        clientSocket.getOutputStream().write(userC.ct);
                        clientSocket.getOutputStream().write(userC.tao.length);
                        clientSocket.getOutputStream().write(userC.tao);
                        if (verbose) System.out.println("Retrieval request for " + userID + "succeeded.");
                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);

                    }
                    break;
                    default:
                        System.out.println("Received an unknown request. Closing connection");
                        continue;
                }

                clientSocket.close();

                if (Thread.interrupted()) {
                    break;
                }

                if (serverListener.isClosed()) {
                    break;
                }
            }
        } finally {
            if (serverListener != null && !serverListener.isClosed()) {
                try {
                    serverListener.close();
                } catch (IOException e) {
                    System.out.println("Error closing server socket.");
                }
            }
        }
    }
}
