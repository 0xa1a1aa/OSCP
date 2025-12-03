# Nmap

## TCP

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:b6:ea:1a:74:33:80:7a:82:17:bb:9e:4b:f9:37:d1 (RSA)
|   256 fa:80:84:a2:e4:3a:2d:1f:8a:9b:23:6e:01:8e:da:be (ECDSA)
|_  256 a4:2f:d9:45:84:88:0f:23:0f:a1:97:ff:43:b1:c3:23 (ED25519)
80/tcp   open  http    Rocket
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     content-type: text/plain; charset=utf-8
|     server: Rocket
|     permissions-policy: interest-cohort=()
|     x-content-type-options: nosniff
|     x-frame-options: SAMEORIGIN
|     content-length: 15
|     date: Mon, 01 Dec 2025 12:54:39 GMT
|     Error Code: 404
|   GetRequest: 
|     HTTP/1.0 200 OK
|     content-type: text/html; charset=utf-8
|     server: Rocket
|     permissions-policy: interest-cohort=()
|     x-content-type-options: nosniff
|     x-frame-options: SAMEORIGIN
|     content-length: 19359
|     date: Mon, 01 Dec 2025 12:54:39 GMT
|     <!DOCTYPE html>
|     <!--[if IE 8 ]>
|     <html lang="en" class="no-js ie8"></html><![endif]-->
|     <!--[if IE 9 ]>
|     <html lang="en" class="no-js ie9"></html><![endif]-->
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="description" content="Booze - Creative HTML Template">
|     <meta name="author" content="createIT">
|     <title>Index - Sogard Brewing Co</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta name="viewport" content="width=device-width initial-scale=1 shrink-to-fit=no">
|     <meta name="format-detection" content="telephone=no">
|     <link rel="stylesheet" href="/assets/css/bootstrap.min.css">
|     <link
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     content-length: 0
|_    date: Mon, 01 Dec 2025 12:54:39 GMT
|_http-title: Index - Sogard Brewing Co
|_http-server-header: Rocket
3000/tcp open  http    Golang net/http server
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Gogs
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=203a99501a832215; Path=/; HttpOnly
|     Set-Cookie: _csrf=I_mVtlRO1lt86iIe7maYfgm3o_06MTc2NDU5MzY3OTYzODk0NTAzNg; Path=/; Domain=10.10.110.21; Expires=Tue, 02 Dec 2025 12:54:39 GMT; HttpOnly
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     Date: Mon, 01 Dec 2025 12:54:39 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="I_mVtlRO1lt86iIe7maYfgm3o_06MTc2NDU5MzY3OTYzOD
|   HTTPOptions: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     X-Content-Type-Options: nosniff
|     Date: Mon, 01 Dec 2025 12:54:39 GMT
|     Content-Length: 108
|_    template: base/footer:15:47: executing "base/footer" at <.PageStartTime>: invalid value; expected time.Time
```

## UDP

```bash

```