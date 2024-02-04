#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2023-2023 xFusion Digital Technologies Co., Ltd. All rights reserved.
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
module: ibmc_modify_storage

short_description: Modify storage controller

version_added: "2.5.0"

description:
    - "Modify properties of the specified storage controller"

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
  storage_controllers:
    required: true
    default: None
    description:
      - Can set one or more storage controller information
  storage_controllers/storage_id:
    required: true
    default: None
    description:
      - ID of the storage resource. It is a mandatory parameter. Format: RAIDStorage+Controller_ID
  storage_controllers/mode:
    required: false
    default: None
    description:
      - Working mode of the RAID controller.  
  storage_controllers/JBOD_state:
    required: false
    default: None
    description:
      - Specifies whether to enable the hard disk pass-through function. 
"""

EXAMPLES = """
  - name: modify storage controller
    ibmc_modify_storage_controller:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      storage_controllers:
       - storage_id: "RAIDStorage0"
         JBOD_state: True
       - storage_id: "RAIDStorage1"
         mode: "JBOD"
"""

RETURNS = """
    {"result": True, "msg": "Modify storage controllers configuration Successfully."}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_storage_controller import modify_storage_controller
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import SERVERTYPE, REQUIRED, TYPE, STR, NO_LOG, LIST
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_modify_storage_controller_module(module):
    """
    Function:
        Modify storage_controller configuration
    Args:
        module: AnsibleModule
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Examples:

    Author:
    Date: 2023/12/8 17:33
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret.get('result'):
            ret = modify_storage_controller(ibmc, module.params)
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {REQUIRED: True, TYPE: STR},
            "ibmc_user": {REQUIRED: True, TYPE: STR},
            "ibmc_pswd": {REQUIRED: True, TYPE: STR, NO_LOG: True},
            "storage_controllers": {REQUIRED: True, TYPE: LIST},
        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_modify_storage_controller_module, module, log, report)


if __name__ == '__main__':
    main()
