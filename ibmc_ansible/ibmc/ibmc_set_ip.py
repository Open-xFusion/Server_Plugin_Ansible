#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_ibmc_ip import set_ibmc_ip
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import is_support_server, set_result, validate_ipv4
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import MSG_FORMAT
from ibmc_ansible.utils import SERVERTYPE

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: ibmc_set_ip

short_description: Set ibmc ip info

version_added: "2.5.0"

description:
    - "Modify iBMC network port information"

options:
  ibmc_ip:
    required: true
    default: None
    description:
      - iBMC IP address.
  ibmc_user:
    required: true
    default: None
    description:
      - iBMC user name used for authentication.
  ibmc_pswd:
    required: true
    default: None
    description:
      - iBMC user password used for authentication.
  target_bmc_ip:
    required: true
    default: None
    description:
      - iBMC IP address.
      - You specify to set network information.
      - You can only choose from the group of hosts.
  ip_version:
    required: false
    default: None
    choices: [IPv4, IPv6, IPv4AndIPv6]
    description:
      - Whether IPv4/IPv6 is enabled.
  ipv4_addr:
    required: false
    default: None
    description:
      - IPv4 address information of the iBMC network port.
  ipv4_addr/address:
    required: false
    default: None
    description:
      - IPv4 address.
  ipv4_addr/subnet_mask:
    required: false
    default: None
    description:
      - Subnet mask of the IPv4 address.
  ipv4_addr/gateway:
    required: false
    default: None
    description:
      - Gateway of the IPv4 address.
  ipv4_addr/address_origin:
    required: false
    default: None
    choices: [Static, DHCP]
    description:
      - How the IPv4 address is allocated.
  ipv6_addr:
    required: false
    default: None
    description:
      - IPv6 address information of the iBMC network port.
  ipv6_addr/address:
    required: false
    default: None
    description:
      - IPv6 address.
  ipv6_addr/prefix_length:
    required: false
    default: None
    description:
      - Prefix length of the IPv6 address, must be an integer.
      - Available Value range is 0 to 128.
  ipv6_addr/address_origin:
    required: false
    default: None
    choices: [Static, DHCPv6]
    description:
      - How the IPv6 address is allocated.
  ipv6_gateway:
    required: false
    default: None
    description:
      - IPv6 gateway address of the iBMC network port.
  hostname:
    required: false
    default: None
    description:
      - iBMC HostName. 
      - Contains a maximum of 64 characters.
      - Including only letters, digits, and hyphens(-). 
      - Cannot start or end with a hyphen.
  domain_name:
    required: false
    default: None
    description:
      - Domain name. 
      - Contains a maximum of 67 characters.
      - The format of FQDN is hostname.domain_name.
      - For example, if hostname is "testhostname" and domain_name is "ibmc.com", then FQDN is "testhostname.ibmc.com".
"""

EXAMPLES = """
 - name:  set ibmc ip
    ibmc_set_ip:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      target_bmc_ip: "192.168.3.11"
      ip_version: "IPv4AndIPv6"
      ipv4_addr:
        - address: "192.168.2.10"
          subnet_mask: "255.255.0.0"
          gateway: "192.168.0.1"
          address_origin: "Static"
      ipv6_addr:
        - address: "fc00:192::10"
          prefix_length: 7
          address_origin: "Static"
      ipv6_gateway: "fc00:192::1"
      hostname: "testhostname"
      domain_name: "ibmc.com"
"""

RETURNS = """
    {"result": True, "msg": "Set iBMC ethernet interface info successful!"}
"""


def ibmc_set_ip_module(module):
    """
    Function:
        Set iBMC ethernet interface configuration
    Args:
              module       (class):

    Returns:
        {"result": False, "msg": 'not run set ibmc ip yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/4 17:33
    """
    ret = {"result": False, "msg": 'not run set ibmc ip yet'}
    current_ibmc_ip = module.params['ibmc_ip']

    # if target_bmc_ip hasn't been specified
    if not module.params.get("target_bmc_ip"):
        log_msg = "No network information is configured because target_bmc_ip hasn't been specified. " \
                  "If you want to configure, please set the target_bmc_ip at set_ibmc_ip.yml."
        set_result(log.warning, MSG_FORMAT % (str(current_ibmc_ip), log_msg), False, ret)
        return ret

    target_bmc_ip = module.params['target_bmc_ip']
    # check target_bmc_ip format
    if not validate_ipv4(target_bmc_ip):
        log_msg = "target_bmc_ip is incorrectly set: %s, please reset it at set_ibmc_ip.yml." % target_bmc_ip
        set_result(log.error, MSG_FORMAT % (str(current_ibmc_ip), log_msg), False, ret)

    # only set network information for target_bmc_ip
    elif target_bmc_ip != current_ibmc_ip:
        log_msg = "Only set network information for %s in the group that you specify." % target_bmc_ip
        set_result(log.warning, MSG_FORMAT % (str(current_ibmc_ip), log_msg), False, ret)

    # Modifying the IP address will result in the inability to delete the original session
    # Cannot create an object with the 'with as' method
    else:
        ibmc = IbmcBaseConnect(module.params, log, report)
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            ret = set_ibmc_ip(ibmc, module.params)
        # close session
        try:
            ibmc.delete_session()
            ibmc.session.close()
        except Exception as e:
            log_msg = "Failed to close session, The error info is: %s" % str(e)
            set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "target_bmc_ip": {"required": True, "type": 'str'},
            "ip_version": {"required": False, "type": 'str'},
            "ipv4_addr": {"required": False, "type": 'list'},
            "ipv6_addr": {"required": False, "type": 'list'},
            "ipv6_gateway": {"required": False, "type": 'str'},
            "hostname": {"required": False, "type": 'str'},
            "domain_name": {"required": False, "type": 'str'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_set_ip_module, module, log, report)


if __name__ == '__main__':
    main()
