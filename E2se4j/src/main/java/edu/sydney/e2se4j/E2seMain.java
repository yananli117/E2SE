package edu.sydney.e2se4j;

public class E2seMain {
    private E2seMain() {
        throw new AssertionError();
    }

    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            System.out.println("The first arg: client/authserver");
            System.out.println("If the first arg is client, second arg is the file path");
            return;
        }

        switch (args[0]) {
            case "client":
                if (args.length < 2) {
                    System.out.println("please specify the source file path in args[1] ");
                } else {
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
                    for (int j = 0; j < 25; j++) {
                        Client client = new Client();
                        client.start(sourceFilePath);
                    }


                }
                break;
            case "authserver":
                System.out.println("This is a running authserver");
                AuthServer server = new AuthServer();
                server.start();
                break;
            default:
                System.out.println("Invalid args, should be client or authserver");
        }
    }
}
