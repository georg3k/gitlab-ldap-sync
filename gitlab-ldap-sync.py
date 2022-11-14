#!/usr/bin/env python3

import gitlab
import sys
import json
import ldap
import ldap.asyncsearch
import logging
import string
import random
import requests

if __name__ == "__main__":

    # Configuration loading
    print('Initializing gitlab-ldap-sync.')
    config = None
    with open('gitlab-ldap-sync.json') as f:
        config = json.load(f)
    if config is not None:
        print('Done.')

        # Logging
        print('Updating logger configuration')
        if not config['gitlab']['group_visibility']:
            config['gitlab']['group_visibility'] = 'private'
        log_option = {
            'format': '[%(asctime)s] [%(levelname)s] %(message)s'
        }
        if config['log']:
            log_option['filename'] = config['log']
        if config['log_level']:
            log_option['level'] = getattr(logging, str(config['log_level']).upper())

        logging.basicConfig(**log_option)
        print('Done.')
        
        # Gitlab authentication
        logging.info('Connecting to GitLab')
        if config['gitlab']['api']:
            gl = None

            if not config['gitlab']['private_token'] and not config['gitlab']['oauth_token']:
                logging.error('You should set authentication in configuration file, aborting.')
            elif config['gitlab']['private_token'] and config['gitlab']['oauth_token']:
                logging.error('You should set one authentication method in in configuration file, aborting.')
            else:
                if config['gitlab']['private_token']:
                    gl = gitlab.Gitlab(url=config['gitlab']['api'], private_token=config['gitlab']['private_token'], ssl_verify=config['gitlab']['ssl_verify'])
                elif config['gitlab']['oauth_token']:
                    gl = gitlab.Gitlab(url=config['gitlab']['api'], oauth_token=config['gitlab']['oauth_token'], ssl_verify=config['gitlab']['ssl_verify'])
                else:
                    gl = None

                if gl is None:
                    logging.error('Cannot create gitlab object, aborting.')
                    sys.exit(1)

            gl.auth()
            logging.info('Done.')

            # LDAP authentication
            logging.info('Connecting to LDAP')
            if not config['ldap']['url']:
                logging.error('You should configure LDAP in config.json')
                sys.exit(1)
            try:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                l = ldap.initialize(uri=config['ldap']['url'])
                l.simple_bind_s(config['ldap']['bind_dn'], config['ldap']['password'])
            except:
                logging.error('Error while connecting')
                sys.exit(1)

            logging.info('Done.')

            # Fetching groups and users from Gitlab
            logging.info('Getting all groups from GitLab.')

            gitlab_groups = []
            gitlab_groups_names = []
            for group in gl.groups.list(all=True):
                gitlab_groups_names.append(group.full_name)
                gitlab_group = {"name": group.full_name, "members": []}
                for member in group.members.list(all=True):
                    user = gl.users.get(member.id)
                    gitlab_group['members'].append({
                        'username': user.username,
                        'name': user.name,
                        'identities': [identity['extern_uid'] for identity in user.identities],
                        'email': user.email
                    })
                gitlab_groups.append(gitlab_group)

            logging.info('Done.')

            # Fetching groups and users from LDAP
            logging.info('Getting all groups from LDAP.')

            ldap_groups = []
            ldap_groups_names = []
            ldap_gids = []
            filterstr = '(&(objectClass=posixGroup)(|'
            for group_filter in config['ldap']['groups_filter']:
                filterstr += '(cn=%s)' % group_filter
            filterstr += '))'
            attrlist=['cn', 'memberUid', 'gidNumber']
            if config['gitlab']['add_description']:
                attrlist.append('description')

            # Fetch users by group membership
            for group_dn, group_data in l.search_s(base=config['ldap']['groups_base_dn'],
                                                   scope=ldap.SCOPE_SUBTREE,
                                                   filterstr=filterstr,
                                                   attrlist=attrlist):
                ldap_gids.append(group_data['gidNumber'])
                ldap_groups_names.append(group_data['cn'][0].decode())
                ldap_group = {"name": group_data['cn'][0].decode(), "members": [], "gidNumber": group_data['gidNumber'][0].decode()}
                if config['gitlab']['add_description'] and 'description' in group_data:
                    ldap_group.update({"description": group_data['description'][0].decode()})
                if 'memberUid' in group_data:
                    for member in group_data['memberUid']:
                        member = member.decode()
                        for user_dn, user_data in l.search_s(base=config['ldap']['users_base_dn'],
                                                             scope=ldap.SCOPE_SUBTREE,
                                                             filterstr='(&(uid=%s)(objectClass=posixAccount))' % member,
                                                             attrlist=['cn', 'uid', 'mail', 'gidNumber', 'sshPublicKey']):
                            ldap_group['members'].append({
                                'username': user_data['uid'][0].decode(),
                                'name': user_data['cn'][0].decode(),
                                'identities': 'cn=%s,%s' % (user_data['cn'][0].decode(), str(config['ldap']['users_base_dn'])),
                                'email': user_data['mail'][0].decode(),
                                'sshPublicKey': [key.decode() for key in user_data['sshPublicKey']][0] if 'sshPublicKey' in user_data.keys() else []
                            })
                ldap_groups.append(ldap_group)

            # Fetch users by primary group
            for user_dn, user_data in l.search_s(base=config['ldap']['users_base_dn'],
                                                    scope=ldap.SCOPE_SUBTREE,
                                                    filterstr='(objectClass=posixAccount)',
                                                    attrlist=['cn', 'uid', 'mail', 'gidNumber', 'sshPublicKey']):
                for ldap_group in ldap_groups:
                    if user_data['gidNumber'][0].decode() == ldap_group['gidNumber']:
                        ldap_group["members"].append({
                            'username': user_data['uid'][0].decode(),
                            'name': user_data['cn'][0].decode(),
                            'identities': 'cn=%s,%s' % (user_data['cn'][0].decode(), str(config['ldap']['users_base_dn'])),
                            'email': user_data['mail'][0].decode(),
                            'sshPublicKey': [key.decode() for key in user_data['sshPublicKey']][0] if 'sshPublicKey' in user_data.keys() else []
                        })
            logging.info('Done.')

            logging.info('Groups currently in GitLab : %s' % str.join(', ', gitlab_groups_names))
            logging.info('Groups currently in LDAP : %s' % str.join(', ', ldap_groups_names))

            # LDAP -> Gitlab Synchronization
            logging.info('Syncing Groups from LDAP.')

            # For every group in LDAP
            for l_group in ldap_groups:
                logging.info('Working on group %s ...' % l_group['name'])

                # Check if there is a corresponding group in Gitlab
                if l_group['name'] not in gitlab_groups_names:

                    # Create Gitlab group if it doesn't exists
                    logging.info('|- Group not existing in GitLab, creating.')
                    gitlab_group = {'name': l_group['name'], 'path': l_group['name'], 'visibility': config['gitlab']['group_visibility']}
                    if config['gitlab']['add_description'] and 'description' in l_group:
                        gitlab_group.update({'description': l_group['description']})
                    g = gl.groups.create(gitlab_group)
                    g.save()
                    gitlab_groups.append({'members': [], 'name': l_group['name']})
                    gitlab_groups_names.append(l_group['name'])
                else:
                    logging.info('|- Group already exist in GitLab, skiping creation.')
                logging.info('|- Working on group\'s members.')

                # For every member in a given LDAP group
                for l_member in l_group['members']:

                    # Check if a given user is present in Gitlab group
                    if l_member['username'] not in [g_member['username'] for g_member in gitlab_groups[gitlab_groups_names.index(l_group['name'])]['members']]:
                        logging.info('|  |- User %s is member in LDAP group but not in GitLab group , adding.' % l_member['name'])
                        g = [group for group in gl.groups.list(search=l_group['name']) if group.name == l_group['name']][0]
                        g.save()
                        u = gl.users.list(search=l_member['username'])

                        # If user exists in Gitlab globally
                        if len(u) > 0:
                            u = u[0]

                            # Add user to corresponding group
                            if u not in g.members.list(all=True):
                                g.members.create({'user_id': u.id, 'access_level': gitlab.DEVELOPER_ACCESS})
                            g.save()

                            # Update admin privileges
                            headers = {
                                'PRIVATE-TOKEN': config['gitlab']['private_token'],
                                'Sudo': 'root'
                            }
                            if l_group['name'] == 'admins':
                                requests.put('%s/api/v4/users/%s?admin=true' % (config['gitlab']['api'], u.id), headers=headers)

                        # If user doesn't exist in Gitlab
                        else:
                            if config['gitlab']['create_user']:
                                logging.info('|  |- User %s does not exist in gitlab, creating.' % l_member['name'])
                                try:

                                    # Create user
                                    user = gl.users.create({
                                        'email': l_member['email'],
                                        'name': l_member['name'],
                                        'username': l_member['username'],
                                        'extern_uid': l_member['identities'],
                                        'provider': config['gitlab']['ldap_provider'],
                                        'password': ''.join(random.choices(string.ascii_lowercase, k=20)),
                                        'admin': True if l_group["name"] == 'admins' else False,
                                        'skip_confirmation': True
                                    })

                                    # Sync SSH public keys
                                    if 'sshPublicKey' in l_member.keys():
                                        for key_idx, key in enumerate(l_member['sshPublicKey']):
                                            user.keys.create({
                                                'title': 'Synced account SSH key #' + str(key_idx),
                                                'key': key
                                            })
                                except gitlab.exceptions as e:
                                    if e.response_code == '409':
                                        user = gl.users.create({
                                            'email': l_member['email'].replace('@', '+gl-%s@' % l_member['username']),
                                            'name': l_member['name'],
                                            'username': l_member['username'],
                                            'extern_uid': l_member['identities'],
                                            'provider': config['gitlab']['ldap_provider'],
                                        'password': ''.join(random.choices(string.ascii_lowercase, k=20)),
                                        'admin': True if l_group["name"] == 'admins' else False,
                                            'skip_confirmation': True
                                        })
                                        
                                        for key_idx, key in enumerate(l_member['sshPublicKey']):
                                            user.keys.create({
                                                'title': 'Synced account SSH key #' + str(key_idx),
                                                'key': key
                                            })

                                # Add user to corresponding group 
                                g.members.create({'user_id': user.id, 'access_level': gitlab.DEVELOPER_ACCESS})
                                g.save()
                            else:
                                logging.info('|  |- User %s does not exist in gitlab, skipping.' % l_member['name'])
                    else:
                        logging.info('|  |- User %s already in gitlab group, updating.' % l_member['name'])

                        users = gl.users.list(search=l_member['username'])

                        if(len(users) > 0):

                            u = users[0]

                            # Sync SSH public keys
                            for key in u.keys.list():
                                if 'Synced account SSH key' in key.title:
                                    u.keys.delete(key.id)
                            u.save()

                            # Update SSH key
                            if 'sshPublicKey' in l_member.keys():
                                for key_idx, key in enumerate(l_member['sshPublicKey']):
                                    try:
                                        u.keys.create({
                                            'title': 'Synced account SSH key #' + str(key_idx),
                                            'key': key
                                        })
                                    except:
                                        logging.error('| |- Failed to set key for user %s' % l_member['name'])

                            # Update admin privileges
                            headers = {
                                'PRIVATE-TOKEN': config['gitlab']['private_token'],
                                'Sudo': 'root'
                            }
                            if l_group['name'] == 'admins':
                                requests.put('%s/api/v4/users/%s?admin=true' % (config['gitlab']['api'], u.id), headers=headers)

                            # If email in LDAP was updated
                            # Important!: waiting for a bug to be fixed: https://gitlab.com/gitlab-org/gitlab/-/issues/25077
                            #if u.email != l_member['email']:
                            #    print('updating mail from %s to %s' % (u.email, l_member['email']))
                            #    new_email = requests.put('%s/api/v4/users/%s?email=%s&skip_reconfirmation=true' % (config['gitlab']['api'], u.id, l_member['email']), headers=headers)
                            #    print('new email: %s' % l_member['email'])
                            #    u = gl.users.list(search=l_member['username'])[0]
                            #    all_emails = u.emails.list()
                            #    all_emails.append(u.email)
                            #    for email in u.emails.list():
                            #        print('checking email: %s' % email.email)
                            #        if str(email.email) != l_member['email']:
                            #            print('deleting email id %s: %s' % (email.id, email.email))
                            #            requests.delete('%s/api/v4/users/%s/emails/%s' % (config['gitlab']['api'], u.id, email.id), headers=headers)

                            # Set name
                            u.name = l_member['name']
                            u.save()

                logging.info('Done.')

            logging.info('Done.')

            logging.info('Cleaning membership of LDAP Groups')

            # For every group in Gitlab
            for g_group in gitlab_groups:
                logging.info('Working on group %s ...' % g_group['name'])
                if g_group['name'] in ldap_groups_names:
                    logging.info('|- Working on group\'s members.')
                    for g_member in g_group['members']:
                        if g_member['username'] == 'root':
                            continue

                        # Remove user from Gitlab group if it was removed from LDAP group
                        if g_member['username'] not in [um['username'] for um in ldap_groups[ldap_groups_names.index(g_group['name'])]['members']]:
                            if str(config['ldap']['users_base_dn']) not in g_member['identities'][0]:
                                logging.info('|  |- Not a LDAP user, skipping.')
                            else:
                                logging.info('|  |- User %s no longer in LDAP Group, removing.' % g_member['name'])
                                g = [group for group in gl.groups.list(search=g_group['name']) if group.name == g_group['name']][0]
                                u = gl.users.list(search=g_member['username'])[0]
                                if u is not None:
                                    g.members.delete(u.id)
                                    g.save()

                                    # Disable admin access if user was removed from 'admins' LDAP group
                                    if g_group['name'] == 'admins':
                                        headers = {
                                            'PRIVATE-TOKEN': config['gitlab']['private_token'],
                                            'Sudo': 'root'
                                            }
                                        requests.put('%s/api/v4/users/%s?admin=false' % (config['gitlab']['api'], u.id), headers=headers)
                        else:
                            logging.info('|  |- User %s still in LDAP Group, skipping.' % g_member['name'])

                    logging.info('|- Done.')
                else:
                    logging.info('|- Not a LDAP group, skipping.')
                    
                logging.info('Done')
        else:
            logging.error('GitLab API is empty, aborting.')
            sys.exit(1)
    else:
        print('Could not load config.json, check if the file is present.')
        print('Aborting.')
        sys.exit(1)