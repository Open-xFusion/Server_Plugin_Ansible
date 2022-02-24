#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: ibmc_https_ca_import
short_description: import https ca
version_added: "2.5.0"
description:
    - "import https ca"

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
  certpath:
    required: true
    default: None
    description:
      - Certificate to be imported which including the path and file name.
      - When the certificate is imported from a remote file server, the format is protocol://ip/folder/file_name
      - The file name extension must be in (".crt", ".cer", ".pem").
  certID:
    required: false
    default: None
    description:
      - ID of the root certificate used to authenticate the remote HTTPS server.
    choices: [5, 6, 7, 8]
  usage:
    required: false
    default: None
    description:
      - certificate usage, available value is FileTransfer.
  import_location:
    required: true
    default: None
    description:
      - location of the certificate.
      - If the certificate is stored in the tmp directory of the BMC, the value is tmp.
      - If the certificate is stored in a local directory, the value is local.
      - If the certificate is stored on a remote file server, the value is the file server protocol.
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
  - name: import https ca
    ibmc_https_ca_import:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      certpath: "/tmp/xFusionCA3.crt"
      certID: 5
      # usage: "FileTransfer"
      import_location: "tmp"
      # file_server_user: "{{sftp_user}}"
      # file_server_pswd: "{{sftp_pswd}}"
"""

RETURNS = """

"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.ibmc_redfish_api.api_https_cert_manage import https_cert_import
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import SERVERTYPE
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_https_ca_import_module(module):
    """
    Function:
        import HTTPS remote file server certificate module
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
        if not ret['result']:
            return ret

        file_type = "ca"
        try:
            ret = https_cert_import(ibmc, module, file_type)
        except Exception as e:
            ret['result'] = False
            ret['msg'] = str(e)
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "certpath": {"required": True, "type": 'str'},
            "certID": {"required": False, "type": 'int'},
            "usage": {"required": False, "type": 'str'},
            "import_location": {"required": True, "type": 'str'},
            "file_server_user": {"required": False, "type": 'str', "no_log": True},
            "file_server_pswd": {"required": False, "type": 'str', "no_log": True}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_https_ca_import_module, module, log, report)


if __name__ == '__main__':
    main()
