# Web applications



## OSINT

* wayback machine [https://archive.org/web/](https://archive.org/web/)
* check github
* google dorking
* Amazon AWS S3 Buckets - The format of the S3 buckets is http(s)://**{name}.**[**s3.amazonaws.com**](http://s3.amazonaws.com/) where {name} is decided by the owner. S3 buckets can be discovered in many ways, such as finding the URLs in the website's page source, GitHub repositories, or even automating the process. One common automation method is by using the company name followed by common terms such as **{name}**-assets, **{name}**-www, **{name}**-public, **{name}**-private, etc.

### Darknet

* TOR
* Freenet
* I2P
* IPFS
* Zeronet

### Blockchain exploring

* Blocktrail
* Bitcoin Who's Who
* Graphsense
* Block Explorer



## Useful tools

* [https://www.wappalyzer.com/](https://www.wappalyzer.com/) online tool and browser extension that helps identify what technologies a website uses, such as frameworks, Content Management Systems (CMS), payment processors and much more, and it can even find version numbers as well.&#x20;
* ffuf  - "ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.32.97/FUZZ" -e .cgi,.bin,.txt -recursion

{% hint style="info" %}
[https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html](https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html)
{% endhint %}

* dirb - "dirb http://10.10.32.97/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt"
* wpscan&#x20;
  * wpscan -u james -P /password.txt -url http://172.16.0.27/test/
