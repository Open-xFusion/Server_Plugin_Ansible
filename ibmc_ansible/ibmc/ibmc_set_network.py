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
---
module: ibmc_set_network

short_description: Batch set ibmc network information

version_added: "2.5.0"

description:
    - "Batch modify iBMC network port information"

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
  domain_name:
    required: false
    default: None
    description:
      - Domain name. 
      - Contains a maximum of 67 characters.
      - The format of FQDN is hostname.domain_name.
      - For example, if hostname is "hostname0" and domain_name is "ibmc.com", then FQDN is "hostname0.ibmc.com".
      - "To view specific domain name format restrictions, please refer to iBMC's documentation
        or iBMC's redfish interface documentation."
  vlan:
    required: false
    default: None
    description:
      - iBMC network port VLAN information.
  vlan/state:
    required: false
    default: None
    choices: [a valid boolean]
    description:
      - Specifies whether VLAN is enabled. 
  vlan/vlan_id:
    required: false
    default: None
    description:
      - Ranges from 1 to 4094. 
  ip_version:
    required: false
    default: None
    choices: [IPv4, IPv6, IPv4AndIPv6]
    description:
      - Whether IPv4/IPv6 is enabled.
  ipv4_subnet_mask:
    required: false
    default: None
    description:
      - Subnet mask of the IPv4 address.
  ipv4_gateway:
    required: false
    default: None
    description:
      - Gateway of the IPv4 address.
  ipv4_address_origin:
    required: false
    default: None
    choices: [Static, DHCP]
    description:
      - How the IPv4 address is allocated.
  ipv6_prefix_length:
    required: false
    default: None
    description:
      - Prefix length of the IPv6 address, must be an integer.
      - Available Value range is 0 to 128.
  ipv6_gateway:
    required: false
    default: None
    description:
      - IPv6 gateway address of the iBMC network port.
  ipv6_address_origin:
    required: false
    default: None
    choices: [Static, DHCPv6]
    description:
      - How the IPv6 address is allocated.
  name_servers:
    required: false
    default: None
    description:
      - Addresses of the preferred and alternate DNS servers if iBMC network port addresses are dynamically allocated. 
      - The server IP address can be an IPv4 or IPv6 address.    
  auto_mode_extend:
    required: false
    default: None
    description:
      - Auto Mode Extensions.  
      - The iBMC version must be iBMC V639 or later, and iBMC 3.03.07.17 or later.
  auto_mode_extend/high_priority_mode:
    required: false
    default: None
    choices: [a valid boolean]
    description:
      - Enabling status of High Priority Port.   
  auto_mode_extend/high_priority_port:
    required: false
    default: None
    description:
      - High Priority Port.  
  auto_mode_extend/high_priority_port/type:
    required: false
    default: None
    choices: [Dedicated, Aggregation, LOM, ExternalPCIe, LOM2, OCP]
    description:
      - Port type.  
  auto_mode_extend/high_priority_port/port_number:
    required: false
    default: None
    description:
      - Silkcreen.
  management_network_port:
    required: false
    default: None
    description:
      - Set the management network port.
  management_network_port/type:
    required: false
    default: None
    choices: [Dedicated, Aggregation, LOM, ExternalPCIe, LOM2, OCP]
    description:
      - Network port type. 
  management_network_port/port_number:
    required: false
    default: None
    description:
      - Silkcreen.
      - For a dedicated network port, this parameter indicates the serial number of the port, not the silkscreen.
  adaptive_port:
    required: false
    default: None
    description:
      - Autonegotiation of each network port.
  adaptive_port/type:
    required: false
    default: None
    choices: [Dedicated, Aggregation, LOM, ExternalPCIe, LOM2, OCP]
    description:
      - Network port type. 
  adaptive_port/port_number:
    required: false
    default: None
    description:
      - Silkscreen.
      - For a dedicated network port, this parameter indicates the serial number of the port, not the silkscreen.
  adaptive_port/adaptive_flag:
    required: false
    default: None
    choices: [a valid boolean]
    description:
      - Autonegotiation flag. 
  dns_address_origin:
    required: false
    default: None
    choices: [IPv4, Static, IPv6]
    description:
      - How DNS IP addresses are allocated.
  private_info_list:
    required: false
    default: None
    description:
      - Private network information list.
  private_info_list/target_bmc_ip:
    required: true
    default: None
    description:
      - iBMC IP address.
      - You specify to set network information.
      - You can only choose from the group of hosts.
  private_info_list/hostname:
    required: false
    default: None
    description:
      - iBMC HostName. 
      - Contains a maximum of 64 characters.
      - Including only letters, digits, and hyphens(-). 
      - Cannot start or end with a hyphen.
  private_info_list/ipv4_addr:
    required: false
    default: None
    description:
      - IPv4 address information of the iBMC network port.
  private_info_list/ipv4_addr/address:
    required: false
    default: None
    description:
      - IPv4 address. 
  private_info_list/ipv4_addr/subnet_mask:
    required: false
    default: None
    description:
      - Subnet mask of the IPv4 address. 
  private_info_list/ipv4_addr/gateway:
    required: false
    default: None
    description:
      - Gateway of the IPv4 address. 
  private_info_list/ipv4_addr/address_origin:
    required: false
    default: None
    choices: [Static, DHCP]
    description:
      - How the IPv4 address is allocated. 
  private_info_list/ipv6_addr:
    required: false
    default: None
    description:
      - IPv6 address information of the iBMC network port.
  private_info_list/ipv6_addr/address:
    required: false
    default: None
    description:
      - IPv6 address. 
  private_info_list/ipv6_addr/prefix_length:
    required: false
    default: None
    description:
      - Prefix length of the IPv6 address, must be an integer. 
      - Available Value range is 0 to 128. 
  private_info_list/ipv6_addr/address_origin:
    required: false
    default: None
    choices: [Static, DHCPv6]
    description:
      - How the IPv6 address is allocated. 
  private_info_list/ipv6_gateway:
    required: false
    default: None
    description:
      - IPv6 gateway address of the iBMC network port. 
  private_info_list/domain_name:
    required: false
    default: None
    description:
      - Domain name. 
      - Contains a maximum of 67 characters.
      - The format of FQDN is hostname.domain_name.
      - For example, if hostname is "hostname0" and domain_name is "ibmc.com", then FQDN is "hostname0.ibmc.com".
      - "To view specific domain name format restrictions, please refer to iBMC's documentation
        or iBMC's redfish interface documentation."
  private_info_list/vlan:
    required: false
    default: None
    description:
      - iBMC network port VLAN information.
  private_info_list/vlan/state:
    required: false
    default: None
    choices: [a valid boolean]
    description:
      - Specifies whether VLAN is enabled. 
  private_info_list/vlan/vlan_id:
    required: false
    default: None
    description:
      - Ranges from 1 to 4094. 
  private_info_list/ip_version:
    required: false
    default: None
    choices: [IPv4, IPv6, IPv4AndIPv6]
    description:
      - Whether IPv4/IPv6 is enabled. 
  private_info_list/name_servers:
    required: false
    default: None
    description:
      - Addresses of the preferred and alternate DNS servers if iBMC network port addresses are dynamically allocated. 
      - The server IP address can be an IPv4 or IPv6 address.    
  private_info_list/auto_mode_extend:
    required: false
    default: None
    description:
      - Auto Mode Extensions.  
      - The iBMC version must be iBMC V639 or later, and iBMC 3.03.07.17 or later.
  private_info_list/auto_mode_extend/high_priority_mode:
    required: false
    default: None
    choices: [a valid boolean]
    description:
      - Enabling status of High Priority Port.   
  private_info_list/auto_mode_extend/high_priority_port:
    required: false
    default: None
    description:
      - High Priority Port. 
  private_info_list/auto_mode_extend/high_priority_port/type:
    required: false
    default: None
    choices: [Dedicated, Aggregation, LOM, ExternalPCIe, LOM2, OCP]
    description:
      - Port type.  
  private_info_list/auto_mode_extend/high_priority_port/port_number:
    required: false
    default: None
    description:
      - Silkscreen.
  private_info_list/management_network_port:
    required: false
    default: None
    description:
      - Set the management network port.
  private_info_list/management_network_port/type:
    required: false
    default: None
    choices: [Dedicated, Aggregation, LOM, ExternalPCIe, LOM2, OCP]
    description:
      - Network port type. 
  private_info_list/management_network_port/port_number:
    required: false
    default: None
    description:
      - Silkscreen.
      - For a dedicated network port, this parameter indicates the serial number of the port, not the silkscreen.
  private_info_list/adaptive_port:
    required: false
    default: None
    description:
      - Autonegotiation of each network port.
  private_info_list/adaptive_port/type:
    required: false
    default: None
    choices: [Dedicated, Aggregation, LOM, ExternalPCIe, LOM2, OCP]
    description:
      - Network port type. 
  private_info_list/adaptive_port/port_number:
    required: false
    default: None
    description:
      - Silkscreen.
      - For a dedicated network port, this parameter indicates the serial number of the port, not the silkscreen.
  private_info_list/adaptive_port/adaptive_flag:
    required: false
    default: None
    choices: [a valid boolean]
    description:
      - Autonegotiation flag.
  private_info_list/dns_address_origin:
    required: false
    default: None
    choices: [IPv4, Static, IPv6]
    description:
      - How DNS IP addresses are allocated.
"""

EXAMPLES = """
  - name: set ibmc network
    ibmc_set_network:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      # Public parameters
      ip_version: "IPv4AndIPv6"
      ipv4_subnet_mask: "255.255.0.0"
      ipv4_gateway: "192.168.0.1"
      ipv4_address_origin: "Static"
      ipv6_prefix_length: 7
      ipv6_gateway: "fc00:192::1"
      ipv6_address_origin: "Static"
      vlan:
        vlan_enable: true
        vlan_id: 1
      dns_address_origin: "Static"
      domain_name: "ibmc.com"
      name_servers:
        - "192.168.10.254"
        - "192.168.10.253"
        - "192.168.10.252"
      network_port_mode: "Fixed"
      management_network_port:
        type: "Dedicated"
        port_number: 1
      auto_mode_extend:
        high_priority_mode: true
        high_priority_port:
          - type: "Dedicated"
            port_number: 1
      adaptive_port:
        - type: "Dedicated"
          port_number: 1
          adaptive_flag: false
      private_info_list:
        # Private parameters
        # The first ip address to be configured
        - target_bmc_ip: "192.168.20.20"
          hostname: "hostname1"
          ipv4_addr:
            - address: "192.168.30.30"
              subnet_mask: "255.255.255.0"
              gateway: "192.168.30.1"
              address_origin: "Static"
          ipv6_addr:
            - address_origin: "DHCPv6"
          vlan:
            vlan_enable: false
          dns_address_origin: "IPv6"
          network_port_mode: "Automatic"
          management_network_port:
            type: "LOM"
            port_number: 1
          adaptive_port:
            - type: "LOM2"
              port_number: 1
              adaptive_flag: true
        # The second ip address to be configured
        - target_bmc_ip: "192.168.40.40"
          hostname: "hostname2"
          ipv4_addr:
            - address: "192.168.50.50"
          ipv6_addr:
            - address: "fc00:192::50"
"""

RETURNS = """
    {"result": True, "msg": "Set iBMC ethernet interface info successful!"}
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.api_manage_ibmc_ip import set_network_info
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import is_support_server, set_result, validate_ipv4, validate_ipv6
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import SERVERTYPE, REQUIRED, TYPE, STR, NO_LOG, LIST, BOOL, INT, ELEMENTS, DICT, OPTIONS


def ibmc_set_network_module(module):
    """
    Function: Set iBMC network information module

    Args:
              module       (class):

    Raises:
        Exception to create or close session
    """
    # Modifying the IP address will result in the inability to delete the original session
    # Cannot create an object with the 'with as' method
    ibmc = IbmcBaseConnect(module.params, log, report)
    ret = {"result": False, "msg": 'not run set ibmc network yet'}
    try:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret.get('result'):
            ret = set_ibmc_network(ibmc, module.params)
    except Exception as e:
        log_msg = "Failed to set iBMC network information, The error info is %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    finally:
        # close session
        try:
            ibmc.delete_session()
        except Exception as e:
            log_msg = "Failed to close session, The error info is: %s" % str(e)
            ibmc.log_error(log_msg)
        finally:
            ibmc.session.close()
    return ret


def set_ibmc_network(ibmc, network_info):
    """
    Function: Set iBMC network information

    Args:
        ibmc: IbmcBaseConnect
        network_info: network information including public and private
    """
    ret = {"result": False, "msg": 'not run set ibmc network yet'}

    # extract public network information from network_info
    public_info = get_public_network_info(network_info)

    # no private network information to set
    if not network_info.get("private_info_list"):
        ret = set_network_info(ibmc, public_info=public_info)
        return ret

    # private network information list
    private_info_list = network_info["private_info_list"]
    ip_count = 0
    equal_ip_index = -1
    ip_correct_flag = True
    ip_list = []
    target_bmc_ip_str = "target_bmc_ip"
    for private_info_dict in private_info_list:
        if private_info_dict.get(target_bmc_ip_str):
            ip_list.append(private_info_dict.get(target_bmc_ip_str))
    if ibmc.ip not in ip_list:
        log_msg = "The ibmc_ip[%s] in hosts is not in target_bmc_ip list" % str(ibmc.ip)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    for private_info_dict in private_info_list:
        if not private_info_dict.get(target_bmc_ip_str):
            log_msg = "private_info_list/%s/target_bmc_ip needs to be set the content." % str(ip_count)
            ibmc.log_error(log_msg)
            ip_correct_flag = False

        target_bmc_ip = private_info_dict[target_bmc_ip_str]
        if not validate_ipv4(target_bmc_ip) and not validate_ipv6(target_bmc_ip):
            log_msg = "private_info_list/%s/target_bmc_ip is wrong IPv4/Ipv6 format: %s" \
                      % (str(ip_count), target_bmc_ip)
            ibmc.log_error(log_msg)
            ip_correct_flag = False

        # if there are more than one equal ip, we use the last piece of network information
        if target_bmc_ip == ibmc.ip:
            equal_ip_index = ip_count

        ip_count += 1

    if not ip_correct_flag:
        log_msg = "There are some problems with target_bmc_ip, please go to the log for details."
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    if equal_ip_index == -1:
        # target_bmc_ip doesn't match which means only using public parameters
        ret = set_network_info(ibmc, public_info=public_info)
    else:
        ret = set_network_info(ibmc, public_info=public_info, private_info=private_info_list[equal_ip_index])
    return ret


def get_public_network_info(network_info):
    """
    Args:
        network_info: public and private network information

    Returns: public network information
    """
    public_info = copy.deepcopy(network_info)
    public_info.pop('private_info_list')
    return public_info


def define_private_info_list():
    """
    Function: define private_info_list format
    """
    private_info_list = {
        TYPE: LIST, ELEMENTS: DICT,
        OPTIONS: {
            "target_bmc_ip": {REQUIRED: True, TYPE: STR},
            "hostname": {TYPE: STR},
            "ipv4_addr": {TYPE: LIST, ELEMENTS: DICT, OPTIONS: {
                "address": {TYPE: STR},
                "subnet_mask": {TYPE: STR},
                "gateway": {TYPE: STR},
                "address_origin": {TYPE: STR}
            }},
            "ipv6_addr": {TYPE: LIST, ELEMENTS: DICT, OPTIONS: {
                "address": {TYPE: STR},
                "prefix_length": {TYPE: INT},
                "address_origin": {TYPE: STR}
            }},
            "ipv6_gateway": {TYPE: STR}
        }
    }
    private_info_list[OPTIONS].update(define_public_arg())
    return private_info_list


def define_public_arg():
    """
    Function: define public argument format
    """
    port_number = "port_number"
    public_arg = {
        "domain_name": {TYPE: STR},
        "vlan": {TYPE: DICT, OPTIONS: {
            "vlan_enable": {TYPE: BOOL},
            "vlan_id": {TYPE: INT}
        }},
        "ip_version": {TYPE: STR},
        "name_servers": {TYPE: LIST, ELEMENTS: STR},
        "network_port_mode": {TYPE: STR},
        "auto_mode_extend": {TYPE: DICT, OPTIONS: {
            "high_priority_mode": {TYPE: BOOL},
            "high_priority_port": {TYPE: LIST, ELEMENTS: DICT, OPTIONS: {
                TYPE: {TYPE: STR},
                port_number: {TYPE: INT}
            }}
        }},
        "management_network_port": {TYPE: DICT, OPTIONS: {
            TYPE: {TYPE: STR},
            port_number: {TYPE: INT}
        }},
        "adaptive_port": {TYPE: LIST, ELEMENTS: DICT, OPTIONS: {
            TYPE: {TYPE: STR},
            port_number: {TYPE: INT},
            "adaptive_flag": {TYPE: BOOL}
        }},
        "dns_address_origin": {TYPE: STR}
    }
    return public_arg


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    network_info_arg = {
        "ibmc_ip": {REQUIRED: True, TYPE: STR},
        "ibmc_user": {REQUIRED: True, TYPE: STR},
        "ibmc_pswd": {REQUIRED: True, TYPE: STR, NO_LOG: True},
        "ipv4_subnet_mask": {TYPE: STR},
        "ipv4_gateway": {TYPE: STR},
        "ipv4_address_origin": {TYPE: STR},
        "ipv6_prefix_length": {TYPE: INT},
        "ipv6_gateway": {TYPE: STR},
        "ipv6_address_origin": {TYPE: STR}
    }
    network_info_arg.update(define_public_arg())
    network_info_arg.update({"private_info_list": define_private_info_list()})
    module = AnsibleModule(argument_spec=network_info_arg, supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_set_network_module, module, log, report)


if __name__ == '__main__':
    main()
