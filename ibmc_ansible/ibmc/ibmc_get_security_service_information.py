#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
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
module: ibmc_get_security_service_information
short_description: get security service information
version_added: "2.5.0"
description:
    - "Get security service information"
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
  - name: get security service information
    ibmc_get_security_service_information:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
"""

RETURNS = """
    {"result": True, "msg": "Get security service information successful!"}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_https_cert_manage import get_security_service_information
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import SERVERTYPE


def ibmc_get_security_service_information_module(module):
    """
    Function:
        Get security service information
    Args:
        module : information from yml
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2021/8/27
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        try:
            ret = get_security_service_information(ibmc)
        except Exception as e:
            ret['result'] = False
            ret['msg'] = str(e)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_get_security_service_information_module, module, log, report)


if __name__ == '__main__':
    main()
