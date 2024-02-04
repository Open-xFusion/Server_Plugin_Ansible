#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2023 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: ibmc_set_web_session_timeout

short_description: Set web session timeout

version_added: "2.5.0"

description:
    - "Set the timeout of a web session in minutes"

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
  web_session_timeout:
    required: true
    default: None
    description:
      - The timeout of a web session in minutes, The value range is 5-480.
"""

EXAMPLES = """
 - name: set web session timeout
    ibmc_set_web_session_timeout :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      web_session_timeout: 420
"""

RETURNS = """
    {"result": True, "msg": "Set web session timeout successfully."}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import SERVERTYPE, REQUIRED, TYPE, STR, NO_LOG, INT
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_web_session import set_web_session_timeout


def ibmc_set_web_session_timeout(module):
    """
    Function:
        Set web session timeout
    Args:
        module : information from yml
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    """

    ret = {'result': False, 'msg': ''}
    web_session_timeout_minutes = module.params["web_session_timeout"]

    if web_session_timeout_minutes < 5 or web_session_timeout_minutes > 480:
        log_msg = 'The timeout range for web sessions is 5-480 minutes, ' \
                  'please set it in the set_web_session_timeout.yml file.'
        set_result(log.error, log_msg, False, ret)
        return ret

    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret.get('result'):
            ret = set_web_session_timeout(ibmc, web_session_timeout_minutes)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {REQUIRED: True, TYPE: STR},
            "ibmc_user": {REQUIRED: True, TYPE: STR},
            "ibmc_pswd": {REQUIRED: True, TYPE: STR, NO_LOG: True},
            "web_session_timeout": {REQUIRED: True, TYPE: INT},
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_set_web_session_timeout, module, log, report)


if __name__ == '__main__':
    main()
