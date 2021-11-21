# glauthid

GLauthid provides a simple, read-only LDAP server for exposing [greenpau/go-identity](https://github.com/greenpau/go-identity) JSON databases. It mostly is just loads the configuration file from the JSON instead of from the original `glauth.conf` file.

GLauthid is used to provide LDAP access along side [caddy-auth-portal](https://github.com/greenpau/caddy-auth-portal) for non-custom applications.

## Usage
The simplest way to run glauthid is to run it via docker-compose with caddy

```yaml
glauth:
  build: glauth/
  volumes:
    - ./caddy/myauth.json:/app/users.json
  ports:
    - 3893:3893
  command: glauth -c /app/users.json -ldap "0.0.0.0:3893"
  restart: "unless-stopped"
```

```
Usage:
  glauth [options] -c <file>
  glauth -h --help
  glauth -version

Options:
  -basedn string
    	LDAP Base domain (default "dc=glauth,dc=local")
  -c string
    	Config file.
  -ldap string
    	ldap bind address
  -ldaps string
    	ldaps bind address
  -ldaps-cert string
    	ldaps certificate
  -ldaps-key string
    	ldaps key
  -v	Debug logging
  -version
    	ldaps key
```

## Issues

go-identity supports many other features (OTP, SSH Key, etc) that are not implemented.