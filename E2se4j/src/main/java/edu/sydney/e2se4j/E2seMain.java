package edu.sydney.e2se4j;


import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class E2seMain {

    public static void main(String[] args) throws Exception {
        if (args.length == 0)
        {
            System.out.println("The first arg: client/authserver; ");
            System.out.println("If the first arg is client, second arg is the path to the source file");
        }
        switch (args[0]) {
            case Constants.CLIENT:
                if(args.length < 2)
                    System.out.println("please specify the source file path in args[1]");
                String sourceFilePath = args[1];
//                    System.out.println("This is a running client only test register give and take procedures.");
//                    System.out.println("Time cost (ms)");
//                    System.out.println("ibOPRF, give, ibOPRF, take");
//                    for (int j = 0; j < 10; j++) {
//                        Client client = new Client();
//                        client.startRGT();
//                    }

                    System.out.println("This is a running client only testing the whole procedure.");
                    System.out.println("The source file path is " + sourceFilePath);
                    System.out.println("time cost (ms)");
                    System.out.println("ibOPRF, give, ibOPRF, take, plainDep, plainRet, secureDepOpt, secureRetOpt, secureDep, secureRet, enc, dec, partNum");

                Properties prop = new Properties();
                InputStream input = null;
                String accessKeyId = null;
                String secretKeyId = null;
                String regionName = null;
                String bucketName = null;

                try {

                    input = new FileInputStream("config.properties");

                    //加载properties文件
                    prop.load(input);

                    //get the property value and print it out

                    accessKeyId = prop.getProperty("accessKeyId");
                    secretKeyId = prop.getProperty("secretKeyId");
                    regionName = prop.getProperty("regionName");
                    bucketName = prop.getProperty("bucketName");
                    //System.out.println(accessKeyId + secretKeyId + regionName + bucketName);


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

                //System.out.println("authserverIP: " + Constants.authServerIp);
                System.out.println("authserverName:  " + Constants.AUTH_SERVER_NAME);
                for (int j = 0; j < 25; j++) {
                    //System.out.println(j);
                        Client client = new Client(accessKeyId, secretKeyId, regionName, bucketName);
                        client.start(sourceFilePath);
                    }
                break;
            case Constants.AUTH_SERVER:
                System.out.println("This is a running authserver");
                AuthServer server = new AuthServer();
                server.start();
                break;
            default:
                System.out.println("Invalid args, should be client and path of source file, or authserver");
        }
    }
}
