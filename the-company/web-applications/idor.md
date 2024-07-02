---
description: >-
  IDOR stands for Insecure Direct Object Reference and is a type of access
  control vulnerability. This type of vulnerability can occur when a web server
  receives user-supplied input to retrieve objects
---

# IDOR

Good places to look for IDORs:

* encoded IDs

![using base64](<../../.gitbook/assets/image (7).png>)

* Hashed IDs

Hashed IDs are a little bit more complicated to deal with than encoded ones, but they may follow a predictable pattern, such as being the hashed version of the integer value. For example, the Id number 123 would become 202cb962ac59075b964b07152d234b70 if md5 hashing were in use.

*   Unpredictable IDs

    If the Id cannot be detected using the above methods, an excellent method of IDOR detection is to create two accounts and swap the Id numbers between them. If you can view the other users' content using their Id number while still being logged in with a different account (or not logged in at all), you've found a valid IDOR vulnerability.

**Where are IDORs located**

The vulnerable endpoint you're targeting may not always be something you see in the address bar. It could be content your browser loads in via an AJAX request or something that you find referenced in a JavaScript file.&#x20;

Sometimes endpoints could have an unreferenced parameter that may have been of some use during development and got pushed to production. For example, you may notice a call to **/user/details** displaying your user information (authenticated through your session). But through an attack known as parameter mining, you discover a parameter called **user\_id** that you can use to display other users' information, for example, **/user/details?user\_id=123**.

{% hint style="info" %}
Do not forget about using Web Developer tools from within the browser; look under network and other places as well.
{% endhint %}

