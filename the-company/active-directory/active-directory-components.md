# Active Directory Components

1. Physical
   1. Data Store - AD DS data store contains the DB files and processes that store and manage directory information for users, services, and applications
      1. consists of NTDS.dit file
      2. is stored by default in the %SystemRoot%\NTDS folder on all domain controllers
      3. is accessible only through the domain controller processes and protocols
   2. Domain controllers - is a server with the AD DS server role installed
      1. host a copy of AD DS directory store
      2. provide auth and authorization services
      3. replicate updates to other DC in the domain and forest
      4. allow administrative access to manage user accounts and network resources
   3. Global catalog server
   4. Read-Only Domain Controller (RODC)



1. Logical
   1. partitions
   2. Schema - defines every type of object that can be stored in the directory; enforces rules regarding object creation and configuration
      1. Class object - User/Computer
      2. Attribute object - Display name
   3. Domains - used to group and manage objects in an organization
   4. Domain trees - hierarchy of domains in AD DS
      1. contoso.com --> emea.contoso.com \
         &#x20;                        \--> na.contoso.com
   5. Forests - collection of domain trees
   6. Sites
   7. Organization Units (OUs) - are AD containers that can contain users, groups, computers, and other OUs
   8. Trusts - Directional/Transitive
   9. Objects
      1. User
      2. InetOrgPerson
      3. Contacts
      4. Groups
      5. Computers
      6. Printers
      7. Shared folders
