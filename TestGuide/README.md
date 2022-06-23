# Test the key server throughput for IBOPRF


## Key server
### Key server requirements
- JDK 8 or larter
- OpenSSL 1.1.1 and libssl-dev
- Nginx
- Tomcat

I show the instructions in ubuntu 18.04

#### Nginx
- install nginx: ```sudo apt install nginx```
- start nginx: ```sudo /etc/init.d/nginx start```

#### libssl-dev
-install libssl-dev in ubuntu as OpenSSL is built-in: ```sudo apt install libssl-dev```


#### Tomcat
- install:
```wget https://dlcdn.apache.org/tomcat/tomcat-9/v9.0.56/bin/apache-tomcat-9.0.56.tar.gz
   mkdir tomcat
   cd tomcat/
   tar -zxvf ~/apache-tomcat-9.0.56.tar.gz
```

- run: ```./tomcat/apache-tomcat-9.0.56/bin/startup.sh```

### Key server configuration

- upload the nginx configuration file directory nginx_conf and the key server package websever1.war
- move the file to tomcat directory: ```mv ./webdemo1.war tomcat/apache-tomcat-9.0.56/webapps/```
- link the configuration file to nginx 
```
   sudo ln -s ~/nginx_config/tomcat_nginx.conf /etc/nginx/sites-enabled/ 
   sudo ln -s ~/nginx_config/tomcat_nginx_ssl.conf /etc/nginx/sites-enabled/
```
- change the nginx configurations
``` 
    vim ~/nginx_config/tomcat_nginx.conf
    vim ~/nginx_config/tomcat_nginx_ssl.conf
```
- reload or restart nginx
```
   sudo nginx -t
   sudo nginx -s reload
```
or ```sudo /etc/init.d/nginx restart```

- start key server```./tomcat/apache-tomcat-9.0.56/bin/startup.sh```

## test client
### test client requirements
- OpenSSL 1.1.1 and libssl-dev
- Siege

#### Siege
```
sudo apt update
sudo apt install siege
siege -V
```

## Test
- test static page, relpace the <iPAddress> with server ip address, run :
   
```siege -c 400 -r 250 "https://<iPAddress>:3443/static.html"```
   
- test IBOPRF, relpace the <iPAddress> with server ip address, run
   
```siege -c 400 -r 250 "https://<iPAddress>:3443/webdemo1/oprf2?uid=user111&ecP=AvJmk/MFsHRH9axY6bugpRrghX8xrWYwQdYap9dy95H2"```

