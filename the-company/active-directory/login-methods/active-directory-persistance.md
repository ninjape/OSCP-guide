# Active Directory Persistance

## Golden Tickets

Going back to the explanation of Kerberos authentication, we recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. This secret key is actually the password hash of a domain user account called krbtgt.696&#x20;

If we are able to get our hands on the krbtgt password hash, we could create our own self-made custom TGTs, or golden tickets.&#x20;

For example, we could create a TGT stating that a non-privileged user is actually a member of the Domain Admins group, and the domain controller will trust it since it is correctly encrypted.



## Domain controller synchronization

DCSYNC
