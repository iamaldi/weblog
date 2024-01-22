---
title:  "[6] CyberPanel - Insecure Generation and Storage of API tokens"
layout: post
author: Altion
date:   2024-01-22
# last_modified_at: 2024-01-22
permalink: /posts/cyberpanel-6
categories: cyberpanel, security research
---

In CyberPanel versions between 1.8.7 and 2.3.4, the user API tokens are insecurely generated using the Base64 transform of the plaintext username and password credentials.

<table>
    <tr>
        <th>OWASP Top 10</th>
        <td><a href="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" target="blank">A02:2021</a> - Cryptographic Failures </td>
    </tr>
    <tr>
        <th>CWE ID</th>
        <td><a href="https://cwe.mitre.org/data/definitions/312.html" target="blank">CWE-312</a> - Cleartext Storage of Sensitive Information</td>
    </tr>
    <tr>
        <th>CVSS v4.0 Score</th>
        <td><a href="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" target="blank">Medium (5.6)</a></td>
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

Compromise of the backend database could expose the plaintext credentials and API tokens of the registered CyberPanel users.

#### Technical Analysis

CyberPanel administrators and resellers can create new user accounts through the 'Create New User' functionality located in the `Users` tab of the main menu.

New accounts are set up with details such as first and last name, e-mail address, role, a limit on the number of websites that can be created by the user, username, password and security level. In addition to these attributes an API token is also generated.

The functionality responsible for creating user accounts is implemented in the `submitUserCreation()` function. On line 171 the `generateToken()` function is called using the username and password as parameters to generate an API token:

```python
# File: userManagment/views.py
116: def submitUserCreation(request):
117:     try:
... 
129:             firstName = data['firstName']
130:             lastName = data['lastName']
131:             email = data['email']
132:             userName = data['userName']
133:             password = data['password']
134:             websitesLimit = data['websitesLimit']
135:             selectedACL = data['selectedACL'] 
... 
171:             token = hashPassword.generateToken(userName, password)
172:             password = hashPassword.hash_password(password)
...
```

The `generateToken()` function is also called (line 373) by the `saveModifications()` function when the account details of existing users are modified:

```python
# File: userManagment/views.py
331: def saveModifications(request):
332:     try:
...
343:             accountUsername = data['accountUsername']
344:             firstName = data['firstName']
345:             lastName = data['lastName']
346:             email = data['email']
... 
373:             token = hashPassword.generateToken(accountUsername, data['passwordByPass'])
374:             password = hashPassword.hash_password(data['passwordByPass'])
...
```

CyberPanel also generates API tokens when it is first installed on the system using the `/usr/local/CyberCP/plogical/adminPass.py` utility. This utility can also be used ad-hoc to reset the password of the `admin` user (lines 48,67):

```python
# File: plogical/adminPass.py
21: def main():
22: 
23:     parser = argparse.ArgumentParser(description='Reset admin user password!')
24:     parser.add_argument('--password', help='New Password')
25:     parser.add_argument('--api', help='Enable/Disable API')
26:     args = parser.parse_args()
27: 
28:     if args.api != None:
... 
43:         numberOfAdministrator = Administrator.objects.count()
44:         if numberOfAdministrator == 0:
45: 
46:             ACLManager.createDefaultACLs()
47:             acl = ACL.objects.get(name='admin')
48:             token = hashPassword.generateToken('admin', adminPass)
49: 
50:             email = 'example@example.org'
51:             admin = Administrator(userName="admin", password=hashPassword.hash_password(adminPass), type=1, email=email,
52:                                   firstName="Cyber", lastName="Panel", acl=acl, token=token)
53:             admin.save()
...
67:         token = hashPassword.generateToken('admin', adminPass)
68:         admin = Administrator.objects.get(userName="admin")
69:         admin.password = hashPassword.hash_password(adminPass)
70:         admin.token = token
71:         admin.save()
...
```

Fundamentally, the `generateToken()` function generates a Base64 transform of the plaintext username and password credentials. Ultimately, this base64-encoded representation is stored in the CyberPanel's database:  

```python
# File: plogical/hashPassword.py
...
15: def generateToken(serverUserName, serverPassword):
16:     credentials = '{0}:{1}'.format(serverUserName, serverPassword).encode()
17:     encoded_credentials = base64.b64encode(credentials).decode()
18:     return 'Basic {0}'.format(encoded_credentials)
```

The following is an output of the SQL query used to list the API tokens of the registered users:

```
MariaDB [cyberpanel]> SELECT id,username,token FROM `loginSystem_administrator`;
+----+----------+----------------------------+
| id | username | token                      |
+----+----------+----------------------------+
|  1 | admin    | Basic YWRtaW46MTIzNDU2Nw== |
+----+----------+----------------------------+
```

In the above example, the 'admin' user's API token can be Base64-decoded to recover the plaintext credentials, 'admin:1234567'.

#### Further Reading

Last one, I promise: [Broken Authentication and Local File Inclusion (LFI) in '/api/FetchRemoteTransferStatus' endpoint](/weblog{% post_url 2024-01-22-cyberpanel-7 %})