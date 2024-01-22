---
layout: post
title:	"Multiple Vulnerabilities in CyberPanel"
author: Altion
date: 2024-01-22
# last_modified_at: 2024-01-22
permalink:	/posts/cyberpanel-0
categories: cyberpanel, security research
tags: pinned
---

In this post I write briefly about the discovery of multiple security vulnerabilities in CyberPanel. Further details on each of the findings are provided separately in dedicated posts.

#### Background

Some time ago I was searching through open source web hosting control panels, and came across CyberPanel[^1]. Setting it up was fairly simple, and the advertised functionality was more than enough for my personal use at the time. After becoming familiar with the available features, I started noticing some interesting behavior. This prompted me to take a closer look and search for potential security vulnerabilities.

At that point, I opened up Burp Suite and combined functional testing with source code review to determine how the different features were implemented. While this was clearly an opportunity for security research, I set specific goals that would keep me on track and allow me to: 

- read through the source code implementation and improve my code review skills in Python codebases
- learn how the developer(s) implemented features and solved (or maybe introduced) problems in code
- identify, analyze, and report potential security vulnerabilities

With the above goals in mind, priority was given to security-critical functionality that could be used to compromise CyberPanel instances.

#### Findings

This short adventure resulted in the discovery of significant vulnerabilities in CyberPanel's functionality and security controls. While more time could be spent on this project, I concluded testing when the following vulnerabilities were identified:

| Security Risk   	| Title 		   																																			|
|:-----------------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Critical 	 		| [WebTerminal Authentication Bypass](/weblog{% post_url 2024-01-22-cyberpanel-1 %})																		|
| Critical	 		| [Authentication Bypass and Local File Inclusion (LFI) in CloudAPI](/weblog{% post_url 2024-01-22-cyberpanel-2 %}) 	  									|
| Critical		 	| [Authentication Bypass in File Manager's Upload Functionality](/weblog{% post_url 2024-01-22-cyberpanel-3 %}) 											|
| Critical	 		| [Security Middleware Bypass](/weblog{% post_url 2024-01-22-cyberpanel-4 %}) 																				|
| High		 		| [Bypass of Security Controls in 'commandInjectionCheck()'](/weblog{% post_url 2024-01-22-cyberpanel-5 %}) 												|
| Medium	 		| [Insecure Generation and Storage of API Tokens](/weblog{% post_url 2024-01-22-cyberpanel-6 %}) 															|
| Medium       		| [Broken Authentication and Local File Inclusion (LFI) in '/api/FetchRemoteTransferStatus' endpoint](/weblog{% post_url 2024-01-22-cyberpanel-7 %}) 		|

This could look like a bit of a mess, and you might be right, to an extent. Before you arrive at that conclusion, take a look at the findings and the maybe at codebase itself. We can then maybe discuss about sharing some headache pills with the potency of tranquilizing an elephant.

#### Timeline

- __July 29, 2023__: Sent an email to CyberPanel's GitHub repository owner. No reply.
- __August 1, 2023__: Sent a LinkedIn message to CyberPanel's GitHub repository owner. No reply.
- __January 4, 2024__: Tagged CyberPanel and its owner's accounts on Twitter asking for security contact details. No reply.
- __January 13, 2024__: Sent an email to CyberPanel support. No reply.
- __January, 20, 2024__: Publication of findings.

As you can see, multiple attempts were made to responsibly disclose these vulnerabilities, however, in each one of them the vendor was unresponsive.

![](../img/mike_g_scott.jpg){:style="display:block; margin-left:auto; margin-right:auto"}

To add to this, there was no security contact or policy on CyberPanel's website and the GitHub repository.

<h5 class="references">References</h5>

[^1]: <a href="https://github.com/usmannasir/cyberpanel" target="_blank">https://github.com/usmannasir/cyberpanel</a>