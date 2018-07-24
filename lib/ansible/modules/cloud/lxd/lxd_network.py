#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Sofiane Medjkoune <sofiane@medjkoune.fr>
# based on lxd_profile by Hiroaki Nakamura <hnakamur@gmail.com>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import print_function

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: lxd_network
short_description: Manage LXD networks
version_added: "2.5"
description:
  - Management of LXD networks
author: "Sofiane Medjkoune"
options:
    name:
        description:
          - Name of a network.
        required: true
    description:
        description:
          - Description of a network.
        required: false
    config:
        description:
          - 'The config for the network (e.g. {"ipv4.address": "172.29.0.1"}).
            See U(https://github.com/lxc/lxd/blob/master/doc/rest-api.md#post-11)'
          - If the network already exists and its "config" value in metadata
            obtained from
            GET /1.0/networks/<name>
            U(https://github.com/lxc/lxd/blob/master/doc/rest-api.md#get-16)
            are different, then this module tries to apply the configurations.
          - If either ipv4.address or ipv6.address are not set in the config
            a value of none will be defaulted.
        required: false
        default:
            ipv4.nat: 'true'
            ipv4.address: 'none'
            ipv6.address: 'none'
    new_name:
        description:
          - A new name of a network.
          - If this parameter is specified a network will be renamed to this name.
            See U(https://github.com/lxc/lxd/blob/master/doc/rest-api.md#post-12)
        required: false
        default: ''
    state:
        choices:
          - present
          - absent
        description:
          - Define the state of a network.
        required: false
        default: present
    url:
        description:
          - The unix domain socket path or the https URL for the LXD server.
        required: false
        default: unix:/var/lib/lxd/unix.socket
    key_file:
        description:
          - The client certificate key file path.
        required: false
        default: '~/.config/lxc/client.key'
    cert_file:
        description:
          - The client certificate file path.
        required: false
        default: '~/.config/lxc/client.crt'
    trust_password:
        description:
          - The client trusted password.
          - You need to set this password on the LXD server before
            running this module using the following command.
            lxc config set core.trust_password <some random password>
            See U(https://www.stgraber.org/2016/04/18/lxd-api-direct-interaction/)
          - If trust_password is set, this module send a request for
            authentication before sending any requests.
        required: false
notes:
  - Networks must have a unique name. If you attempt to create a network
    with a name that already existed in the users namespace the module will
    simply return as "unchanged".
'''

EXAMPLES = '''
# An example for creating a network
- hosts: localhost
  connection: local
  tasks:
    - name: Create a network
      lxd_network:
        name: lxdbr0
        state: present
        config:
          ipv4.address: none
          ipv6.address: 2001:470:b368:4242::1/64
          ipv6.nat: "true"
        description: My network

# An example for creating a network via http connection
- hosts: localhost
  connection: local
  tasks:
  - name: create lxdbr0 bridge
    lxd_network:
      url: https://127.0.0.1:8443
      # These cert_file and key_file values are equal to the default values.
      #cert_file: "{{ lookup('env', 'HOME') }}/.config/lxc/client.crt"
      #key_file: "{{ lookup('env', 'HOME') }}/.config/lxc/client.key"
      trust_password: mypassword
      name: lxdbr0
      state: present
      config:
        bridge.driver: openvswitch
        ipv4.address: 10.0.3.1/24
        ipv6.address: fd1:6997:4939:495d::1/64
      description: My network

# An example for deleting a network
- hosts: localhost
  connection: local
  tasks:
    - name: Delete a network
      lxd_network:
        name: lxdbr0
        state: absent

# An example for renaming a network
- hosts: localhost
  connection: local
  tasks:
    - name: Rename a network
      lxd_network:
        name: lxdbr0
        new_name: lxdbr1
        state: present
'''


RETURN = '''
old_state:
  description: The old state of the network
  returned: success
  type: string
  sample: "absent"
logs:
  description: The logs of requests and responses.
  returned: when ansible-playbook is invoked with -vvvv.
  type: list
  sample: "(too long to be placed here)"
actions:
  description: List of actions performed for the network.
  returned: success
  type: list
  sample: '["create"]'
'''


import os
import ast

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.lxd import LXDClient, LXDClientException


HOME = os.environ['HOME']

KEY_ACTIONS = 'actions'
KEY_CHANGED = 'changed'
KEY_LOGS = 'logs'
KEY_MSG = 'msg'
KEY_OLD_STATE = 'old_state'

ACTION_CREATE = 'create'
ACTION_RENAME = 'rename'
ACTION_UPDATE = 'update'
ACTION_DELETE = 'delete'

KEY_DEFAULT = 'default'
KEY_CHOICES = 'choices'
KEY_REQUIRED = 'required'
KEY_TYPE = 'type'

TYPE_STR = 'str'
TYPE_DICT = 'dict'

VAL_AUTO = 'auto'
VAL_TRUE = 'true'
VAL_NONE = 'none'
VAL_ERROR = 'error'

STATE_PRESENT = 'present'
STATE_ABSENT = 'absent'

KEY_METADATA = 'metadata'

PARAM_NAME = 'name'
PARAM_STATE = 'state'
PARAM_DESCRIPTION = 'description'
PARAM_NEW_NAME = 'new_name'
PARAM_URL = 'url'
PARAM_KEY_FILE = 'key_file'
PARAM_CERT_FILE = 'cert_file'
PARAM_TRUST_PASSWORD = 'trust_password'
PARAM_CONFIG = 'config'

KEYS_LXD_CONFIG = [
    PARAM_NAME,
    PARAM_DESCRIPTION,
    PARAM_CONFIG
]

DEFAULT_URL = 'unix:/var/lib/lxd/unix.socket'
DEFAULT_HUMAN_READABLE_KEY_FILE = '~/.config/lxc/client.key'
DEFAULT_HUMAN_READABLE_CERT_FILE = '~/.config/lxc/client.crt'

KEY_IPV4_ADDR = 'ipv4.address'
KEY_IPV4_NAT = 'ipv4.nat'
KEY_IPV6_ADDR = 'ipv6.address'

DEFAULT_LXD_CONFIG = {
    KEY_IPV4_NAT: VAL_TRUE,
    KEY_IPV4_ADDR: VAL_NONE,
    KEY_IPV6_ADDR: VAL_NONE
}

ARGUMENT_SPEC = {
    PARAM_NAME: {
        KEY_TYPE: TYPE_STR,
        KEY_REQUIRED: VAL_TRUE,
    },

    PARAM_NEW_NAME: {
        KEY_TYPE: TYPE_STR
    },

    PARAM_CONFIG: {
        KEY_TYPE: TYPE_DICT,
        KEY_DEFAULT: DEFAULT_LXD_CONFIG
    },

    PARAM_DESCRIPTION: {
        KEY_TYPE: TYPE_STR,
        KEY_DEFAULT: ''
    },

    PARAM_STATE: {
        KEY_CHOICES: [
            STATE_PRESENT,
            STATE_ABSENT
        ],
        KEY_DEFAULT: STATE_PRESENT
    },

    PARAM_URL: {
        KEY_TYPE: TYPE_STR,
        KEY_DEFAULT: DEFAULT_URL
    },

    PARAM_KEY_FILE: {
        KEY_TYPE: TYPE_STR,
        KEY_DEFAULT: DEFAULT_HUMAN_READABLE_KEY_FILE
    },

    PARAM_CERT_FILE: {
        KEY_TYPE: TYPE_STR,
        KEY_DEFAULT: DEFAULT_HUMAN_READABLE_CERT_FILE
    },

    PARAM_TRUST_PASSWORD: {
        KEY_TYPE: TYPE_STR
    }
}


def lxd_get_network(client, name):
    return client.do(
        'GET',
        '/1.0/networks/{}'.format(name),
        ok_error_codes=[404])


def lxd_create_network(client, name, config):
    client.do(
        'POST',
        '/1.0/networks',
        config)


def lxd_replace_network(client, name, config):
    client.do(
        'PUT',
        '/1.0/networks/{}'.format(name),
        config)


def lxd_rename_network(client, name, new_name):
    client.do(
        'POST',
        '/1.0/networks/{}'.format(name),
        {PARAM_NAME: new_name})


def lxd_delete_network(client, name):
    client.do(
        'DELETE',
        '/1.0/networks/{}'.format(name))


def read_module_config(config):
    if config is None:
        return DEFAULT_LXD_CONFIG
    else:
        return ast.literal_eval(config)


def make_lxd_config(name=None,
                    description='',
                    inner_config=None):
    return {
        PARAM_NAME: name,
        PARAM_DESCRIPTION: description,
        PARAM_CONFIG: inner_config
    }



def is_update_required(module_config, lxd_config):
    # Check if description changed.
    module_description = module_config.get(PARAM_DESCRIPTION, "")
    lxd_description = lxd_config.get(PARAM_DESCRIPTION, "")
    if module_description != lxd_description:
        return True

    # Check if inner config changed.
    module_inner_config = module_config.get(PARAM_CONFIG, {})
    lxd_inner_config = lxd_config.get(PARAM_CONFIG, {})

    # Keys of the items in module_inner_config having 'auto' as their value.
    module_inner_config_auto_keys = [k
                                     for k, v in module_inner_config.items()
                                     if v == VAL_AUTO]

    module_inner_config_without_auto = \
        {k: v
         for k, v in module_inner_config.items()
         if k not in module_inner_config_auto_keys}

    # lxd_inner_config modified as such:
    #   - has the same keys as module_inner_config
    #   - if the key has not an 'auto' value in module_config
    #     or its value is 'none' then it is kept.
    common_lxd_inner_config = {k: v
                               for k, v in lxd_inner_config.items()
                               if (k in module_inner_config.keys() and
                                   (k not in module_inner_config_auto_keys or
                                    v == VAL_NONE))}

    if common_lxd_inner_config != module_inner_config_without_auto:
        return True

    return False


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=False)

    debug = module._verbosity >= 4
    actions = []

    url = module.params[PARAM_URL]
    key_file = module.params.get(PARAM_KEY_FILE, None)
    cert_file = module.params.get(PARAM_CERT_FILE, None)

    try:
        client = LXDClient(
            url,
            key_file=key_file,
            cert_file=cert_file,
            debug=debug)
    except LXDClientException as e:
        module.fail_json(msg=e.msg)

    trust_password = module.params.get(PARAM_TRUST_PASSWORD, None)

    if trust_password is not None:
        client.authenticate(trust_password)

    name = module.params[PARAM_NAME]
    description = module.params[PARAM_DESCRIPTION]
    state = module.params[PARAM_STATE]
    new_name = module.params.get(PARAM_NEW_NAME, None)

    try:
        lxd_net = lxd_get_network(client, name)
        lxd_net_state = (STATE_ABSENT
                         if lxd_net[KEY_TYPE] == VAL_ERROR
                         else STATE_PRESENT)

        module_inner_config = module.params.get(PARAM_CONFIG, None)
        module_config = make_lxd_config(
            name=name,
            description=description,
            inner_config=module_inner_config)
        lxd_config = lxd_net.get(KEY_METADATA, {})

        if state == STATE_PRESENT:

            if lxd_net_state == STATE_ABSENT:
                if new_name is None:
                    lxd_create_network(client, name,
                                       module_config)
                    actions.append(ACTION_CREATE)
                else:
                    module.fail_json(
                        msg=str("The 'new_name' parameter must not be "
                                "provided when the specified network "
                                "does not exist and the required state "
                                "is 'present'."),
                        changed=False)

            else:  # lxd_net_state == STATE_PRESENT

                if new_name is not None and new_name != name:
                    lxd_rename_network(client, name, new_name)
                    name = new_name
                    actions.append(ACTION_RENAME)

                if is_update_required(module_config, lxd_config):
                    lxd_replace_network(client, name, module_config)
                    actions.append(ACTION_UPDATE)

        else:  # state == STATE_ABSENT

            if lxd_net_state == STATE_PRESENT:
                if new_name is None:
                    lxd_delete_network(client, name)
                    actions.append(ACTION_DELETE)
                else:
                    module.fail_json(
                        msg=str("The 'new_name' parameter must not be "
                                "provided when the specified network "
                                "does not exist and the required state "
                                "is 'absent'."),
                        changed=False)

    except LXDClientException as e:
        result = {
            KEY_MSG: e.msg,
            KEY_CHANGED: len(actions) > 0,
            KEY_ACTIONS: actions
        }

        if client.debug:
            result[KEY_LOGS] = client.logs

        module.fail_json(**result)

    else:
        result = {
            KEY_CHANGED: len(actions) > 0,
            KEY_OLD_STATE: lxd_net_state,
            KEY_ACTIONS: actions
        }

        if client.debug:
            result[KEY_LOGS] = client.logs

        module.exit_json(**result)


if __name__ == '__main__':
    main()
