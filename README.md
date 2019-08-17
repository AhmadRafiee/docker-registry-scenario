# Private docker registry 

Create private docker registry and authenticate proxy with nginx

## Installation

**Step1**: Create the required directories.

```bash
mkdir -p auth data
```

**Step2**: Create the main nginx configuration. Paste this code block into a new file called auth/nginx.conf:

```bash
events {
    worker_connections  1024;
}

http {

  upstream docker-registry {
    server registry:5000;
  }

  ## Set a variable to help us decide if we need to add the
  ## 'Docker-Distribution-Api-Version' header.
  ## The registry always sets this header.
  ## In the case of nginx performing auth, the header is unset
  ## since nginx is auth-ing before proxying.
  map $upstream_http_docker_distribution_api_version $docker_distribution_api_version {
    '' 'registry/2.0';
  }

  server {
    listen 443 ssl;
    server_name SUB.DOMAIN.TLD;

    # SSL
    ssl_certificate /etc/nginx/conf.d/fullchain.pem;
    ssl_certificate_key /etc/nginx/conf.d/privkey.pem;

    # Recommendations from https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    # disable any limits to avoid HTTP 413 for large image uploads
    client_max_body_size 0;

    # required to avoid HTTP 411: see Issue #1486 (https://github.com/moby/moby/issues/1486)
    chunked_transfer_encoding on;

    location /v2/ {
      # Do not allow connections from docker 1.5 and earlier
      # docker pre-1.6.0 did not properly set the user agent on ping, catch "Go *" user agents
      if ($http_user_agent ~ "^(docker\/1\.(3|4|5(?!\.[0-9]-dev))|Go ).*$" ) {
        return 404;
      }

      # To add basic authentication to v2 use auth_basic setting.
      auth_basic "Registry realm";
      auth_basic_user_file /etc/nginx/conf.d/nginx.htpasswd;

      ## If $docker_distribution_api_version is empty, the header is not added.
      ## See the map directive above where this variable is defined.
      add_header 'Docker-Distribution-Api-Version' $docker_distribution_api_version always;

      proxy_pass                          http://docker-registry;
      proxy_set_header  Host              $http_host;   # required for docker client's sake
      proxy_set_header  X-Real-IP         $remote_addr; # pass on real client's IP
      proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
      proxy_set_header  X-Forwarded-Proto $scheme;
      proxy_read_timeout                  900;
    }
  }
  server {
      listen 80;
      server_name SUB.DOMAIN.TLD;
      return 301 https://$host$request_uri;
  }
}
```

**Step3**: Create a password file auth/nginx.htpasswd for “USER” and “PASSWORD”

```bash
docker run --rm --entrypoint htpasswd registry:2 -Bbn USER PASSWORD > auth/nginx.htpasswd
```

**Step4**: Create certificate with [letsencrypt](https://letsencrypt.org/)  and copy to the auth/ directory.
 
 install certbot
```bash
#centos:
yum install certbot
#ubuntu:
apt install certbot
```
Create Certificate with certbot command
```bash
certbot certonly --standalone --agree-tos -d SUB.DOMAIN.TLD
```
Copy certificate file

```bash
cp /etc/letsencrypt/archive/SUB.DOMAIN.TLD/fullchain1.pem auth/fullchain.pem
cp /etc/letsencrypt/archive/SUB.DOMAIN.TLD/privkey1.pem auth/privkey.pem
```

**Step5**: Create docker network 
```bash
docker network create hub
docker network ls 
```

**Step6**: Create and run registry container
```bash
docker run -d -p 127.0.0.1:5000:5000 -v ${PWD}/data:/var/lib/registry --net hub --restart=always --name registry registry:2
```
**Step7**: Create and run nginx container
```bash
docker run -d -p 443:443 -v ${PWD}/auth:/etc/nginx/conf.d -v ${PWD}/auth/nginx.conf:/etc/nginx/nginx.conf:ro \
--net hub --restart=always --name web nginx:alpine
```
**Step8**: Container running test and login to the registry
```bash
docker ps 
docker login https://SUB.DOMAIN.TLD -u USER -p PASSWORD
```
**Step9**: Image tagging and push to the registry
```bash
docker tag nginx:latest SUB.DOMAIN.TLD/nginx:test
docker push SUB.DOMAIN.TLD/nginx:test
```


## License
[DockerMe.ir](https://dockerme.ir)

## Reference
[docker](https://docs.docker.com/registry/recipes/nginx/)
