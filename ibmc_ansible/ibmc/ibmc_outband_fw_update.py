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
module: ibmc_outband_fw_update
short_description: update outband firmware
version_added: "2.5.0"
description: update outband firmware
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
  local_file:
    required: false
    default: None
    description:
      - local firmware path
  remote_file:
    required: false
    default: None
    description:
      - remote firmware path or bmc file path
  file_server_user:
    required: false
    default: None
    description:
      - remote file server user name
  file_server_pswd:
    required: false
    default: None
    description:
      - remote file server password
"""

EXAMPLES = r"""
  - name: update outband fw
    ibmc_outband_fw_update:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      local_file: "/home/plugin/cpldimage.hpm"
"""

RETURNS = """

"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.ibmc_redfish_api.api_outband_fw_update import update_fw
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import SERVERTYPE, REQUIRED, TYPE, STR, NO_LOG
from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import remote_file_path


def ibmc_outband_fw_update_module(module):
    """
    Function: Outband firmware upgrade
    Args:
        module : information from yml
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/10/9 20:30
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret.get('result'):
            all_file = (module.params.get("local_file"), module.params.get("remote_file"))
            if all(all_file) or not any(all_file):
                log_error = "Please select an out-of-band firmware upgrade " \
                            "mode from local_file and remote_file."
                set_result(ibmc.log_error, log_error, False, ret)
                return ret
        try:
            local, file, protocol = get_file_name(module)
        except Exception as e:
            log_error = "Update failed! %s" % str(e)
            set_result(ibmc.log_error, log_error, False, ret)
            return ret

        ret = update_fw(ibmc, file, protocol, local)
    return ret


def get_file_name(module):
    """
    Function: Obtain the name of the upgrade package.
    Args:
        module: information from yml
    Returns:
        local: Whether to upload the upgrade package from the local host
        file: the name of the upgrade package
        protocol: File Server Protocol
    """
    protocol = None
    local = False
    file = module.params.get("local_file") or module.params.get("remote_file")
    if file == module.params.get("local_file"):
        local = True
    elif not file.startswith("/tmp"):
        file = remote_file_path(file, module)
        protocol, server_path = file.split("://")
        protocol = protocol.upper()
    return local, file, protocol


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {REQUIRED: True, TYPE: STR},
            "ibmc_user": {REQUIRED: True, TYPE: STR},
            "ibmc_pswd": {REQUIRED: True, TYPE: STR, NO_LOG: True},
            "local_file": {REQUIRED: False, TYPE: STR},
            "remote_file": {REQUIRED: False, TYPE: STR},
            "file_server_user": {REQUIRED: False, TYPE: STR, NO_LOG: True},
            "file_server_pswd": {REQUIRED: False, TYPE: STR, NO_LOG: True}
        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_outband_fw_update_module, module, log, report)


if __name__ == '__main__':
    main()
