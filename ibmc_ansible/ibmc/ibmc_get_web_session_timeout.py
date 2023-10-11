#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2023 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import SERVERTYPE
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_web_session import get_web_session_timeout

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: ibmc_get_web_session_timeout

short_description: Get web session timeout

version_added: "2.5.0"

description:
    - "Get the timeout of a web session in minutes"

options:
  ibmc_ip:
    required: true
    default: None
    description:
      - iBMC IP address
  ibmc_user:
    required: true
    default: None
    description:
      - iBMC user name used for authentication
  ibmc_pswd:
    required: true
    default: None
    description:
      - iBMC user password used for authentication
"""

EXAMPLES = """
 - name: get web session timeout
    ibmc_get_web_session_timeout :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
"""

RETURNS = """
    {"result": True, "msg": "Get web session timeout successfully."}
"""


def ibmc_get_web_session_timeout(module):
    """
    Function:
        Get the timeout of a web session in minutes
    Args:
        module : information from yml
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret.get('result'):
            ret = get_web_session_timeout(ibmc)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_get_web_session_timeout, module, log, report)


if __name__ == '__main__':
    main()
