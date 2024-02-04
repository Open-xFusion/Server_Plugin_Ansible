#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2023-2023 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_drive import modify_drive_status
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import SERVERTYPE, REQUIRED, TYPE, STR, NO_LOG, LIST
from ibmc_ansible.utils import ansible_ibmc_run_module

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
module: ibmc_modify_drive
short_description: modify drive configuration
version_added: "2.5.0"
description: modify drive configuration
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
 drives:
    required: true
    default: None
    description:
      - Can set one or more drives mode
  drives/drive_id:
    required: true
    default: None
    description:
      - ID of the drives resource. It is a mandatory parameter.
  drives/firmware_status:
    required: true
    default: None
    description: 
      - The firmware status mode that needs to be set
"""
EXAMPLES = r"""
 - name: modify drive
    ibmc_modify_drive:
          ibmc_ip: "{{ ibmc_ip }}"
          ibmc_user: "{{ ibmc_user }}"
          ibmc_pswd: "{{ ibmc_pswd }}"
          drives:
            - drive_id: "HDDPlaneDisk0"
              firmware_status: "UnconfiguredGood"
            - drive_id: "HDDPlaneDisk1"
              firmware_status: "JBOD"
            - drive_id: "HDDPlaneDisk1"
              firmware_status: "Online"
"""

RETURNS = """

"""


def ibmc_modify_drive_module(module):
    """
    Function:
        modify drive module
    Args:
        module       (class):
    Returns:
        ret = {"result": True, "msg": "Modify disk successful!"}
    Raises:
        Exception
    Examples:
    Date: 2023/12/7 20:30
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret.get('result'):
            ibmc.is_write_file = True
            ret = modify_drive_status(ibmc, module.params)
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {REQUIRED: True, TYPE: STR},
            "ibmc_user": {REQUIRED: True, TYPE: STR},
            "ibmc_pswd": {REQUIRED: True, TYPE: STR, NO_LOG: True},
            "drives": {REQUIRED: True, TYPE: LIST}

        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_modify_drive_module, module, log, report)


if __name__ == '__main__':
    main()
