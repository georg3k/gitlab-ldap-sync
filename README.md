## Python LDAP -> Gitlab synchronization script
This script mimics some of Gitlab EE paid version features regarding LDAP synchronization. It is meant to be used with OpenLDAP schema and self-hosted Gitlab instance. However it can me modified to be compliant with Active Directory or some other LDAP provider. 
Features:
- Gitlab API authentication based on private token or oauth token
- LDAP -> Gitlab groups mapping
    - Can be restricted to sync only certain groups in configuration file
    - Can update group description based on LDAP group description
- LDAP -> Gitlab users mapping
    - Can be restricted to sync only existent users in configuration file
    - Respects both primary group and group entities in LDAP
    - Email synchronization
    - SSH keys synchronization (multiple keys supported)
- Automatically grant admin users Gitlab admin and root privileges
- Logging for scheduled usage
