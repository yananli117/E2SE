# E2SE4j
A Java prototype for paper 
"End-to-Same-End Encryption: Modularly Augmenting an App with an Efficient, Portable, and Blind Cloud Storage"

## Description
E2SE is a system for securely storing private data in the cloud with the help of a key server (an App server).
With this system, a user could use one password to have access to the private data at any device. 
The plain data is visible to the legitimate user with correct password on client side and blind to both the cloud and key server.

Our implementation includes a client and a key server (only the part for secure storage). We use AWS S3 as the sotrage cloud.
The supported operations that users could do are as following:
- **Register:** Users register
- **Give:** User share the data encryption key with the key server and cloud server 
- **Take:** User reconstruct the data enncryption key with the key server and cloud server
- **Secure Deposit:** User encrypt data using the data encryption key, and upload to the cloud server
- **Secure Retrieve:** User retrieve the encrypted data from the cloud server and decrypt it.

# Installation
Download the full repository fot both the client and key server.

## Requirements
### software requirements on both client and key server

- JDK 8 or later
- Maven 3.8.1 or later
- OpenSSL and libssl-dev

### hardware requirement to the client: 
- Users should have a security credential to access the AWS S3 server. We just provide a private security credential to access the AWS S3 for the Usenix artifact evaluation. If any user want to test/use this prototype, plaese first login AWS console via https://aws.amazon.com/ with your own AWS account and  apply the security credential to programically access the AWS S3. If users want to use other cloud storage services, the implementation of Client class should be modified a bit to apply to the APIs the storage cloud provides. So far the proviided prototype only support AWS S3 as the storage server.

- the client and key server could be. deployed on different devices for standard use. It is ok to run two processes for the client and key server in one device to verify the function.

## Preparation
Please make sure the above requirements are sattisfied fist and prepare the following. 

### security credential to access the AWS S3
Given your own security credential, you can set the accessKeyId and secretKeyId in the code.

### certificates for TLS communication
During the communication between client and key server/cloud server, the client authenticates key server and cloud server via servers' certificates.
The cloud server certificate is already trusted by any devices installing JDK.  We need to produce the certificate for the key server and let client trust the key server certificate.

The configurations are as follows:

- generate key server certificate

We have generated the self-signed CA root certificate using OpenSSL, and use it to sign the key server certificate. You can find the required certificates in E2se4j/certificateNew.

- turst the key server certificate on client side by importing the certificate of key server into the Java cacerts keystore

Here we take the certificates in E2se4j/certificateNew as an example and and show the import method in Linux command line:
```
cp ./E2se4j/certificateNew/ca-certificate.pem $JAVA_HOME/jre/lib/security 
cd $JAVA_HOME/jre/lib/security
sudo chmod 777 cacerts #obtain the permission if needed
keytool -import -v -trustcacerts -alias theCARootNew -file ./ca-certificate.pem -keystore cacerts -storepass changeit
```
enter Yes to trust it and you can check the certificate is installed successfully:
```keytool -list -keystore cacerts -alias theCARootNew ```

If you use the certificates from other ways or change the storepass, please remember to change the certificate information of the authserver in the code. 

Concretely, in Constant.java class, the AUTH_SERVER_KEYSTORE_PATH, AUTH_SERVER_KEYSTORE_PASSWORD, AUTH_SERVER_NAME imformation should be modified.

### key server ip
- on the client side, before compiling, configure the key server ip address in the Constant.java class, say the AUTH_SERVER_ADDRESS information.


## Compile
Without specification, the client and key server follow the same instructions. 

Please make sure your devices satisfy the above requirements and the preparation is finished. Especially, the credential of S3 should be configured in the Client class.

Then enter the directory E2se4j. 

Compile and package : ``` mvn clean package ```

Copy the produced jar package E2se4j-1.0-SNAPSHOT-jar-with-dependencies.jar in the target directory to the E2se4j directory:

``` cp ./target/E2se4j-1.0-SNAPSHOT-jar-with-dependencies.jar ./```

## Run
Firstly, run the key server under the E2se4j directory:
```java -jar E2se4j-1.0-SNAPSHOT-jar-with-dependencies.jar "authserver" ```

Secondly, run the client under the E2se4j directory:
```java -jar E2se4j-1.0-SNAPSHOT-jar-with-dependencies.jar "client" “path of a file to deposit” ```

Thirdly, keep the key server running, and re-run the client with different sizes of files.

## Test

###  Efficiency test
follow the run instructions, take a file as input and get the output. The output varies with different file sizes.

You can follow the listing commands to generate a file of n megabytes
  ```
  cd TestGuide
  javac ComFile1.java
  java ComFile1 n 
  ```
###  Throughput test
follow the instructions in TestGuild/README.md to install dependencies and the benchmark tool (Siege), configure key server and test client, and test the throughput of key server.
