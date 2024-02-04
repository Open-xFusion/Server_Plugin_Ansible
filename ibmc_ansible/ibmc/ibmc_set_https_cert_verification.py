#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
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
module: ibmc_set_https_cert_verification
short_description: set https cert verification
version_added: "2.5.0"
description: set https cert verification
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
    default:
    description:
      - iBMC user password used for authentication
  verify_cmd:
    required: true
    default: None
    description:
      - Enabling or disabling certificate verification for the HTTPS remote file server.
"""

EXAMPLES = r"""
  - name: set https cert verification
    ibmc_set_https_cert_verification:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      verify_cmd: True
"""

RETURNS = """

"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.ibmc_redfish_api.api_https_cert_manage import set_https_cert_verification
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import SERVERTYPE, REQUIRED, TYPE, STR, NO_LOG, BOOL
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_https_ca_delete_module(module):
    """
    Function:
        Set HTTPS remote file server certificate module
    Args:
        module : information from yml
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2021/8/20 20:30
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if not ret.get('result'):
            return ret

        try:
            ret = set_https_cert_verification(ibmc, module)
        except Exception as e:
            ret['result'] = False
            ret['msg'] = str(e)
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {REQUIRED: True, TYPE: STR},
            "ibmc_user": {REQUIRED: True, TYPE: STR},
            "ibmc_pswd": {REQUIRED: True, TYPE: STR, NO_LOG: True},
            "verify_cmd": {REQUIRED: True, TYPE: BOOL},
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_https_ca_delete_module, module, log, report)


if __name__ == '__main__':
    main()
