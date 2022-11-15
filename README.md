# gitlab-ldap-sync

Python project to sync LDAP Groups into GitLab.

This script mimics some of Gitlab EE paid version features regarding LDAP synchronization. It is meant to be used with OpenLDAP and self-hosted Gitlab instance. However it can me modified to be compliant with Active Directory or some other LDAP provider as well. You can schedule this script using cron to keep your Gitlab users and groups in sync continuously. This is a fork of [MrBE4R/gitlab-ldap-sync](https://github.com/MrBE4R/gitlab-ldap-sync) project. Not all original features were preserved, but some new were added.

Features:
- Gitlab API authentication based on private token or oauth token
- LDAP -> Gitlab groups mapping
    - Can be restricted to sync only certain groups
    - Can update group description based on LDAP group description
- LDAP -> Gitlab users mapping
    - Can be restricted to sync only existent users
    - Respects both primary group in and separate group entities in LDAP
    - Email synchronization
    - SSH keys synchronization
- Automatically grant admin users Gitlab admin and root privileges
- Logging for scheduled usage


> **Note**
> LDAP auth still needs to be enabled in your Gitlab instance settings. This feaure is available in free version of Gitlab CE and EE.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

This project has been tested on CentOS 7, CentOS 8 Stream and GitLab 12.4.* and OpenLDAP.

```
Python
pip3
python-gitlab
python-ldap
```

### Installing

You could either install requirements system wide or use virtual environment / conda, choose your poison.

To get this up and running you just need to do the following :

* Clone the repo
```bash
git clone https://github.com/georg3k/gitlab-ldap-sync
```
* Install requirements
```bash
pip3 install -r ./gitlab-ldap-sync/requirements.txt
```
* Edit gitlab-ldap-sync.json with you values
```bash
EDITOR ./gitlab-ldap-sync/gitlab-ldap-sync.json
```
* Start the script and enjoy your sync users and groups being synced
```bash
cd ./gitlab-ldap-sync && ./gitlab-ldap-sync.py
```

You should get something like this :
```bash
Initializing gitlab-ldap-sync.
Done.
Updating logger configuration
Done.
Connecting to GitLab
Done.
Connecting to LDAP
Done.
Getting all groups from GitLab.
Done.
Getting all groups from LDAP.
Done.
Groups currently in GitLab : < G1 >, < G2 >, < G3 >, < G4 >, < G5 >, < P1 >, < P2 >, < P3 >
Groups currently in LDAP : < G1 >, < G2 >, < G3 >, < G4 >, < G5 >, < G6 >, < G7 > 
Syncing Groups from LDAP.
Working on group <Group Display Name> ...
|- Group already exist in GitLab, skiping creation.
|- Working on group's members.
|  |- User <User Display Name> already in gitlab group, skipping.
|  |- User <User Display Name> already in gitlab group, skipping.
[...]
|- Done.
[...]
Done
```

You could add the script in a cron to run it periodically.
## Deployment

How to configure config.json
```json5
{
  "log": "/var/log/gitlab-ldap-sync.log",
  "log_level": "INFO",
  "gitlab": {
    "api": "https://gitlab.example.com",                 // Gitlab API URL
    "ssl_verify": true,                                  // Verify SSL certificate
    "private_token": "gitlab_token",                     // Gitlab API token
    "oauth_token": "",                                   // Gitlab OAuth token
    "ldap_provider": "LDAP",                             // LDAP provider name
    "create_user": true,                                 // Create users if they're not present in Gitlab
    "group_visibility": "internal",                      // Default group visibility for synced groups
    "add_description": true                              // Sync group description 
  },
  "ldap": {
    "url": "ldaps://ldap.example.com",                   // LDAP server URL
    "users_base_dn": "ou=People,dc=example,dc=com",      // LDAP tree users location
    "groups_base_dn": "ou=group,dc=example,dc=com",      // LDAP tree groups location
    "bind_dn": "cn=readonly,dc=example,dc=com",          // LDAP bind username
    "password": "ldap_password",                         // LDAP bind password
    "groups_filter": ["admins", "developers", "testers"] // LDAP groups to sync
  }
}
```
You should use ```private_token``` or ```oauth_token``` but not both. Check [the gitlab documentation](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#creating-a-personal-access-token) for how to generate the personal access token.

```create_user``` If set to true, the script will create the users in gitlab and add them in the corresponding groups. Be aware that gitlab will send a mail to every new users created.

## Built With

* [Python](https://www.python.org/)
* [python-ldap](https://www.python-ldap.org/en/latest/)
* [python-gitlab](https://python-gitlab.readthedocs.io/en/stable/)


## Authors

Original project is made by [MrBE4R](https://github.com/MrBE4R) and [mape2k](https://github.com/mape2k), reworked edition presented in this repository is made by [georg3k](https://github.com/georg3k).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (original MIT license is preserved).

