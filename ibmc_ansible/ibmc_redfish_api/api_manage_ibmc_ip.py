#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os
import requests

from ibmc_ansible.utils import validata_ipv4_in_gateway
from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import IBMC_REPORT_PATH
from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import validate_ipv4
from ibmc_ansible.utils import validate_ipv6
from ibmc_ansible.utils import RESULT, MSG

IP_DICT = {
    "ipv4andipv6": "IPv4AndIPv6",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "static": "Static",
    "dhcp": "DHCP",
    "dhcpv6": "DHCPv6"
}
TYPE_DICT = {
    "dedicated": "Dedicated",
    "aggregation": "Aggregation",
    "lom": "LOM",
    "externalpcie": "ExternalPCIe",
    "lom2": "LOM2",
    "ocp": "OCP"
}
MODE_DICT = {
    "fixed": "Fixed",
    "automatic": "Automatic"
}
DNS_ADDRESS_ORIGIN_DICT = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "static": "Static"
}

# Minimum perfix length
MIN_PREFIX_LEN = 0
# Maximum perfix length
MAX_PREFIX_LEN = 128

HOSTNAME = "hostname"
FQDN = "FQDN"
IP_V4 = "IPv4"
IP_V6 = "IPv6"
IP_VERSION = "ip_version"
IP_VERSION_REDFISH = "IPVersion"
IPV4_ADDR = "ipv4_addr"
IPV6_ADDR = "ipv6_addr"
IPV6_GATEWAY = "ipv6_gateway"
VLAN = "vlan"
DNS_ADDRESS_ORIGIN = "dns_address_origin"
DOMAIN_NAME = "domain_name"
NAME_SERVERS = "name_servers"
NETWORK_PORT_MODE = "network_port_mode"
MANAGEMENT_NETWORK_PORT = "management_network_port"
AUTO_MODE_EXTEND = "auto_mode_extend"
ADAPTIVE_PORT = "adaptive_port"
HOST_NAME = "HostName"


def set_ibmc_ip(ibmc, ip_info):
    """
    Function:
        Modify iBMC network port information.
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
              ip_info           (dict):    User-set IP information
    Returns:
        {"result": True, "msg": "Set iBMC ethernet interface info successful!"}
    Raises:
        Set ibmc ethernet interface info failed!
    Examples:
        None
    Author:
    Date: 2019/9/23 21:21
    """
    ibmc.log_info("Start set iBMC ip...")
    # Get the current IP version
    oem_info = ibmc.oem_info
    request_result_json = get_ibmc_ip_request(ibmc)
    try:
        current_ip = {}
        curr_ip_version = request_result_json["Oem"][oem_info][IP_VERSION_REDFISH]
        current_ip["curr_ip_version"] = curr_ip_version
        current_ip[HOSTNAME] = request_result_json.get(HOST_NAME)
    except Exception as e:
        ibmc.log_error("Get iBMC current ip failed! The error info is: %s \n" % str(e))
        raise e

    # Check whether the user configuration is valid in advance.
    ip_info_check = check_information(ibmc, ip_info, current_ip)
    if not ip_info_check.get(RESULT):
        return ip_info_check

    # Obtain user-configured IP information
    ip_version = ip_info.get(IP_VERSION)
    ipv4_addr = ip_info.get(IPV4_ADDR)
    ipv6_addr = ip_info.get(IPV6_ADDR)
    ipv6_gateway = ip_info.get(IPV6_GATEWAY)
    hostname = ip_info.get(HOSTNAME)
    domain_name = ip_info.get('domain_name')

    # Verify the legality of the IPv4 address, IPv6 address and IPv6 gateway
    verify_result = validate_ip_address(ibmc, ipv4_address_list=ipv4_addr,
                                        ipv6_address_list=ipv6_addr,
                                        ipv6_gateway=ipv6_gateway)
    if not verify_result.get(RESULT):
        return verify_result

    # Initialize payload
    ip_addr_payload = {}
    if ipv4_addr:
        ip_addr_payload['IPv4Addresses'] = convert_ipv4_addr(ipv4_addr)
    if ipv6_addr:
        ip_addr_payload['IPv6Addresses'] = convert_ipv6_addr(ipv6_addr)
    if ipv6_gateway:
        ip_addr_payload['IPv6DefaultGateway'] = ipv6_gateway
    if hostname:
        ip_addr_payload['HostName'] = hostname
    if domain_name:
        if hostname:
            ip_addr_payload[FQDN] = hostname + '.' + domain_name
        elif current_ip.get(HOSTNAME):
            ip_addr_payload[FQDN] = current_ip.get(HOSTNAME) + "." + domain_name
        else:
            ip_addr_payload[FQDN] = domain_name
            log_msg = "The host name is empty. Setting the domain name assigns \
                      the first field of the domain name to the host name."
            ibmc.log_info(log_msg)
    ret = set_ip_result(ibmc, ip_addr_payload, ip_version, curr_ip_version)

    return ret


def set_ip_result(ibmc, ip_address_payload, ip_version, current_ip_version):
    """
    Function:
        Set the IP address and return the setting result.
    Args:
        ibmc: Class that contains basic information about iBMC
        ip_address_payload: IP address to be set
        ip_version: IP_version information to be set
        current_ip_version: Current IP address on the BMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    # Initialize return information
    ret = {RESULT: True, MSG: ''}
    oem_info = ibmc.oem_info
    # parameter in the yml file
    prepare_change_version = False

    if ip_address_payload:
        # Prepare for changing IP_version and IP_addr at the same time.
        if ip_version is not None and ip_version != current_ip_version:
            if current_ip_version != "IPv4AndIPv6":
                prepare_ret = prepare_ip_version(ibmc)
                if not prepare_ret.get(RESULT):
                    return prepare_ret

                prepare_change_version = True
        # Set iBMC IP address
        log_massage = "ethernet interface"
        ret = set_ibmc_ip_request(ibmc, ip_address_payload, log_massage)

    # If the setting fails, restore IP_version.
    if not ret.get(RESULT):
        if prepare_change_version:
            log_info = "Failed to change IP_addr. Restore IP_version."
            ibmc.log_info(log_info)
            restore_res = restore_ip_version(ibmc, current_ip_version)
            if not restore_res.get(RESULT):
                log_error = "Failed to change IP_addr! Failed to restore IP_version!"
                set_result(ibmc.log_error, log_error, False, ret)
                return ret
        return ret

    # Set IP version
    if not ip_version:
        pass
    elif ip_version == "IPv4AndIPv6" and prepare_change_version:
        version_msg = "Set ip_version successful"
        set_result(ibmc.log_info, version_msg, True, ret)
    else:
        ip_version_payload = {"Oem": {oem_info: {IP_VERSION_REDFISH: ip_version}}}
        ret = set_ibmc_ip_request(ibmc, ip_version_payload,
                                  log_massage=IP_VERSION)

        if not ret.get(RESULT):
            return ret

    if ip_version and ip_address_payload:
        log_msg = "Set ip_addr successful! Set ip_version successful!"
        set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def prepare_ip_version(ibmc):
    """
    Function:
        To ensure successful setting, set ip_version to IPv4AndIPv6.
    Args:
        ibmc: Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    oem_info = ibmc.oem_info
    log_info = "Change IP_Version to IPv4AndIPv6 and " \
               "prepare for the change of ip_addr."
    ibmc.log_info(log_info)
    ip_prepare_version = "IPv4AndIPv6"
    payload_prepare = {"Oem": {oem_info: {IP_VERSION_REDFISH: ip_prepare_version}}}
    ret = set_ibmc_ip_request(ibmc, payload_prepare, log_massage="preparing")
    return ret


def restore_ip_version(ibmc, current_ip_version):
    """
    Function:
        If the setting fails, restore ip_version to the current state.
    Args:
        ibmc: Class that contains basic information about iBMC
        current_ip_version: Current IP address on the BMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    oem_info = ibmc.oem_info
    restore_payload = {"Oem": {oem_info: {IP_VERSION_REDFISH: current_ip_version}}}
    ret = set_ibmc_ip_request(ibmc, restore_payload, "ip_version restoring")

    return ret


def check_information(ibmc, ip_information, current_ip):
    """
    Function:
        Check whether the settings transferred by the user are proper.
    Args:
        ibmc: Class that contains basic information about iBMC
        ip_information: IP address set by the user
        current_ip: Current IP address on the BMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    ret = {RESULT: True, MSG: ''}
    log_error = None

    # Obtain user-configured IP information
    ip_version = ip_information.get(IP_VERSION)
    ip_version = IP_DICT.get(str(ip_version).lower())
    ipv4_addr = ip_information.get(IPV4_ADDR)
    ipv6_addr = ip_information.get(IPV6_ADDR)
    ipv6_gateway = ip_information.get(IPV6_GATEWAY)
    current_version = current_ip.get("curr_ip_version")
    hostname = ip_information.get(HOSTNAME)
    domain_name = ip_information.get('domain_name')

    # If the input parameter is empty, prompt the user to enter the correct
    param = (ip_version, ipv4_addr, ipv6_addr, ipv6_gateway, hostname, domain_name)
    if not any(param):
        log_msg = 'The input parameter is empty, please enter the correct ' \
                  'parameter in the set_ibmc_ip.yml file. '
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # If IP_version is not modified, ensure that the current IP_version supports the modified IP_addr.
    if not ip_version:
        if current_version == IP_V4 and (ipv6_addr or ipv6_gateway):
            log_error = "The current IP_version is IPv4 enabled. " \
                        "The ipv6_addr or ipv6_gateway cannot be set." \
                        " Please reconfigure the setting."
        elif current_version == IP_V6 and ipv4_addr:
            log_error = "The current IP_version is IPv6 enabled. " \
                        "The ipv4_addr cannot be set." \
                        " Please reconfigure the setting."

    # Ensure that the modified ip_version supports the modified ip_addr.
    elif ip_version == IP_V4:
        if ipv6_addr or ipv6_gateway:
            log_error = "When IP_version is set to IPv4, the setting of ipv6_addr " \
                        "or ipv6_gateway becomes invalid and cannot continue." \
                        " Please reconfigure the setting."
        elif (not ipv4_addr) and (current_version == IP_V6):
            log_error = "The current IPv4_addr does not exist. Please configure an IPv4_addr. "

    elif ip_version == IP_V6:
        if ipv4_addr:
            log_error = "When IP_version is set to IPv6, the setting of ipv4_addr " \
                        " becomes invalid and cannot continue." \
                        " Please reconfigure the setting."
        elif (not ipv6_addr) and (current_version == IP_V4):
            log_error = "The current IPv6_addr does not exist. Please configure an IPv6_addr. "

    elif ip_version != "IPv4AndIPv6":
        log_error = "The ip version is incorrect, it should be 'IPv4', 'IPv6' or 'IPv4AndIPv6'."

    if log_error is not None:
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    log_info = "Check user configuration successful!"
    set_result(ibmc.log_info, log_info, True, ret)
    return ret


def set_ibmc_ip_request(ibmc, payload, log_massage):
    """
    Function:
        Sends an IP address setting request to the BMC.
    Args:
        ibmc: Class that contains basic information about iBMC
        payload: Request body
        log_massage: Set content description.
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    # Initialize return information
    ret = {RESULT: True, MSG: ''}
    # Obtain ethernet interface_id
    ethernet_interface_id = get_ethernet_interface_id(ibmc)
    if not ethernet_interface_id:
        ret[RESULT] = False
        ret[MSG] = 'Set iBMC ethernet interface info failed!'
        return ret
    # URL of the iBMC network port information
    url = "%s/EthernetInterfaces/%s" % (ibmc.manager_uri, ethernet_interface_id)
    # Obtain etag
    etag = ibmc.get_etag(url)
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}
    try:
        # Modify iBMC ip version by PATCH method
        request_result = ibmc.request('PATCH', resource=url, headers=headers,
                                      data=payload, tmout=10)
    except Exception as e:
        log_msg = "Set iBMC %s failed! The error info is: %s \n" % (log_massage, str(e))
        ibmc.log_error(log_msg)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    # Obtain the error code
    request_code = request_result.status_code
    if request_code == 200:
        log_msg = "Set iBMC %s successful!" % log_massage
        set_result(ibmc.log_info, log_msg, True, ret)
        request_result_dict = request_result.json()
        # It means there was an error but a success code '200' was returned
        print_message(ibmc, request_result_dict)
        return ret
    else:
        log_msg = "Set iBMC %s failed! The error code is: %s, " \
                  "The error info is: %s." % (log_massage, str(request_code),
                                              str(request_result.json()))
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret


def print_message(ibmc, response_dict):
    """

    Function: print response message

    """
    # It means there was an error but a success code '200' was returned
    if response_dict.get('@Message.ExtendedInfo'):
        msg_extend_info = response_dict['@Message.ExtendedInfo']
        for msg_info in msg_extend_info:
            ibmc.log_warn("There is an error message here: %s. " % msg_info)


def get_ibmc_ip(ibmc):
    """
    Function:
        Query network port information of the manager resource.
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
    Returns:
        {"result": True, "msg": "Get iBMC ethernet interface info successful!"}
    Raises:
        None
    Examples:
         None
    Author:
    Date: 2019/9/24 11:48
    """
    ibmc.log_info("Start get iBMC ip...")

    # Initialize return information
    ret = {RESULT: True, MSG: ''}
    # File to save iBMC network port information
    result_file = os.path.join(IBMC_REPORT_PATH, "ibmc_ip",
                               "%s_iBMCIPInfo.json" % str(ibmc.ip))

    # Get the return result of the redfish interface
    request_result_json = get_ibmc_ip_request(ibmc)

    # Write the result to a file
    result = {
        "PermanentMACAddress": request_result_json.get("PermanentMACAddress"),
        HOST_NAME: request_result_json.get(HOST_NAME),
        FQDN: request_result_json.get(FQDN),
        "VLAN": request_result_json.get("VLAN"),
        "NameServers": request_result_json.get("NameServers"),
        "IPv4Addresses": request_result_json.get("IPv4Addresses"),
        "IPv6Addresses": request_result_json.get("IPv6Addresses"),
        "IPv6DefaultGateway": request_result_json.get("IPv6DefaultGateway"),
        "IPv6StaticAddresses": request_result_json.get("IPv6StaticAddresses"),
        "Oem": request_result_json.get("Oem")
    }
    write_result(ibmc, result_file, result)

    # Update ret
    ret[RESULT] = True
    ret[MSG] = "Get iBMC ethernet interface info successful! " \
               "For more detail information please refer to %s." % result_file

    ibmc.log_info("Get iBMC ethernet interface info successful!")
    return ret


def get_ibmc_ip_request(ibmc):
    """
    Function:
        Get the return result of the redfish interface
    Args:
              ibmc            :   Class that contains basic information about iBMC
    Returns:
        result of the redfish interface
    Raises:
        Get iBMC ethernet interface info failed!
    Examples:
        None
    Author:
    Date: 2019/10/26 10:55
    """
    # Get ethernet interface id
    ethernet_interface_id = get_ethernet_interface_id(ibmc)
    if ethernet_interface_id is None:
        ibmc.log_error("Get iBMC ethernet interface info failed!")
        raise Exception("Get iBMC ethernet interface info failed!")

    # URL of the iBMC network port information
    url = "%s/EthernetInterfaces/%s" % (ibmc.manager_uri, ethernet_interface_id)

    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    try:
        # Obtain the network port information of the iBMC through the GET method
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            error = "Get iBMC ethernet interface info failed!" \
                    "The error code is: %s. The error info is: %s" \
                    % (str(request_code), str(request_result.json()))
            ibmc.log_error(error)
            raise Exception(error)
        else:
            request_result_json = request_result.json()
    except Exception as e:
        error = "Get iBMC ethernet interface info failed! " \
                "The error info is: %s" % str(e)
        ibmc.log_error(error)
        raise requests.exceptions.RequestException(error)

    return request_result_json


def validate_ip_address(ibmc, ipv4_address_list=None, ipv6_address_list=None, ipv6_gateway=None):
    """
    Function:
        Verify the legality of the IP address
    Args:
        ibmc:
              ipv4addr_list            (list):   IPv4 address info
              ipv6addr_list            (list):   IPv6 address info
              ipv6gateway              (str):    IPv6 gateway
    Returns:
        True or error info
    Raises:
        The IPv4 address is invalid. or
        The IPv6 address is invalid. or
        The IPv6 gateway is invalid.
    Examples:
        None
    Author:
    Date: 2019/10/8 15:55
    """
    # Initialize return information
    ret = {RESULT: True, MSG: ''}
    # if IPv4 address info is not None
    if ipv4_address_list:
        # Determine the data type of IPv4 address info
        if not isinstance(ipv4_address_list, list):
            log_msg = "The IPv4 address format is incorrect, please set it in the set_ibmc_ip.yml file."
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        for ipv4 in ipv4_address_list:
            log_msg = check_ipv4(ipv4)
            if log_msg is not None:
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

    # if IPv6 address info is not None
    if ipv6_address_list:
        # Determine the data type of IPv6 address info
        if not isinstance(ipv6_address_list, list):
            log_msg = "The IPv6 address format is incorrect, please set it in the set_ibmc_ip.yml file."
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        for ipv6 in ipv6_address_list:
            log_msg = check_ipv6(ipv6, ipv6_gateway)
            if log_msg is not None:
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

    # if IPv6 gateway is not None
    if ipv6_gateway:
        log_msg = None
        # Determine the data type of IPv6 gateway
        if not isinstance(ipv6_gateway, str):
            log_msg = "The IPv6 gateway format is incorrect, please set it in the set_ibmc_ip.yml file"
        elif not validate_ipv6(ipv6_gateway):
            log_msg = "The IPv6 gateway is invalid."

        if log_msg is not None:
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    log_msg = "Verify the IP address successful"
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def check_ipv6(ipv6, ipv6_gateway):
    log_msg = None
    ipv6_address = ipv6.get("address")
    ipv6_prefix_length = ipv6.get("prefix_length")
    ipv6_address_origin = ipv6.get("address_origin")
    # Verify address
    if not validate_ipv6(ipv6_address):
        log_msg = "The IPv6 address is invalid."
    # Verify prefix_length
    if ipv6_prefix_length is not None:
        # Verify ipv6_prefix_length is an integer
        if not isinstance(ipv6_prefix_length, int):
            log_msg = "The IPv6 prefix length is invalid, it must be a integer."
        try:
            if ipv6_prefix_length < MIN_PREFIX_LEN or ipv6_prefix_length > MAX_PREFIX_LEN:
                log_msg = "The IPv6 prefix length is invalid, the value ranges from %s to %s." % (
                    str(MIN_PREFIX_LEN), str(MAX_PREFIX_LEN))
        except ValueError:
            log_msg = "The IPv6 prefix length is invalid."
    # Verify address origin
    if ipv6_address_origin:
        if ipv6_address_origin.lower() == "static":
            pass
        # When the IPv6 address origin is DHCPv6:
        # 1.The IPV6 address and prefix length cannot be set at the same time;
        # 2.Gateway setting is not allowed.
        elif ipv6_address_origin.lower() == "dhcpv6":
            if ipv6_address or (ipv6_prefix_length is not None):
                log_msg = "The request for IPv6Addresses modification failed " \
                          "because the value of IPv6Addresses/AddressOrigin is DHCPv6."
            elif ipv6_gateway:
                log_msg = "The request for the property IPv6DefaultGateway modification failed " \
                          "because the address is in DHCPv6 mode."
        else:
            log_msg = "The IPv6 address origin is incorrect, it should be 'Static' or 'DHCPv6'."
    return log_msg


def check_ipv4(ipv4):
    log_msg = None
    ipv4_address = ipv4.get("address")
    ipv4_subnet_mask = ipv4.get("subnet_mask")
    ipv4_gateway = ipv4.get("gateway")
    ipv4_address_origin = ipv4.get("address_origin")
    # Verity address, subnet_mask, gateway
    if not validate_ipv4(ipv4_address):
        log_msg = "The IPv4 address is invalid."
    elif not validate_ipv4(ipv4_subnet_mask):
        log_msg = "The IPv4 subnet mask is invalid."
    elif not validate_ipv4(ipv4_gateway):
        log_msg = "The IPv4 gateway is invalid."
    elif ipv4_address_origin:
        # When the IPv4 address origin is Static, the IP address and gateway are on the same network segment.
        if ipv4_address_origin.lower() == "static":
            if not validata_ipv4_in_gateway(ipv4_address, ipv4_gateway,
                                            ipv4_subnet_mask):
                log_msg = "The IPv4 address and gateway are not on the same network segment."
        # When the IPv4 address origin is DHCP, cannot set the IPv4 address, subnet mask, and gateway.
        elif ipv4_address_origin.lower() == "dhcp":
            if ipv4_address or ipv4_subnet_mask or ipv4_gateway:
                log_msg = "The request for IPv4Addresses modification failed " \
                          "because the value of IPv4Addresses/AddressOrigin is DHCP."
        else:
            log_msg = "The IPv4 address origin is incorrect, it should be 'Static' or 'DHCP'."
    return log_msg


def get_ethernet_interface_id(ibmc):
    """

    Function:
        Query network port collection information of the manager resource
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
    Returns:
        ethernet interface id
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/9 19:29
    """

    # Initialize ethernet interface id
    ethernet_interface_id = None

    # URL of the network port collection information
    url = "%s/EthernetInterfaces" % ibmc.manager_uri

    try:
        # Obtain the network port collection information of the manager resource through the GET method
        request_result = ibmc.request('GET', resource=url, tmout=10)

        if request_result.status_code == 200:
            data = request_result.json()
        else:
            ibmc.log_error("Get iBMC ethernet interface id failed! "
                           "The error code is: %s. The error info is: %s." %
                           (str(request_result.status_code), str(request_result.json())))
            return ethernet_interface_id

        # Obtain ethernet interface id
        odata_id = data["Members"][0]["@odata.id"]
        ethernet_interface_id = odata_id.split('/')[-1]
        ibmc.log_info("Get iBMC ethernet interface id successful!")
    except Exception as e:
        ibmc.log_error(
            "Get iBMC ethernet interface id failed! The error info is: %s." % str(
                e))
    return ethernet_interface_id


def convert_ipv4_addr(ipv4_address_list):
    """

    Function:
        Convert IPv4 address format
    Args:
              ipv4_address_list            (list):   IPv4 address list
    Returns:
        list
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/26 22:25
    """
    result_list = []
    for ipv4_addr in ipv4_address_list:
        result_dict = {}
        address = ipv4_addr.get("address")
        gateway = ipv4_addr.get("gateway")
        subnet_mask = ipv4_addr.get("subnet_mask")
        address_origin = ipv4_addr.get("address_origin")
        if address:
            result_dict["Address"] = address
        if gateway:
            result_dict["Gateway"] = gateway
        if subnet_mask:
            result_dict["SubnetMask"] = subnet_mask
        if address_origin:
            result_dict["AddressOrigin"] = IP_DICT.get(
                str(address_origin).lower())
        if result_dict:
            result_list.append(result_dict)
    return result_list


def convert_ipv6_addr(ipv6_address_list):
    """

    Function:
        Convert IPv6 address format
    Args:
              ipv6_address_list            (list):   IPv6 address list
    Returns:
        list
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/26 22:32
    """
    result_list = []
    for ipv6_addr in ipv6_address_list:
        result_dict = {}
        address = ipv6_addr.get("address")
        prefix_length = ipv6_addr.get("prefix_length")
        address_origin = ipv6_addr.get("address_origin")
        if address:
            result_dict["Address"] = address
        if prefix_length is not None:
            result_dict["PrefixLength"] = prefix_length
        if address_origin:
            result_dict["AddressOrigin"] = IP_DICT.get(
                str(address_origin).lower())
        if result_dict:
            result_list.append(result_dict)
    return result_list


def set_network_info(ibmc, public_info, private_info=None):
    """
    Function: combine and set network information

    Args:
        ibmc: IbmcBaseConnect
        public_info: public network information
        private_info: private network information
    """
    if private_info is None:
        private_info = {}
    ibmc.log_info("Start set iBMC network information...")

    ret = {RESULT: True, MSG: 'not set network information yet'}
    # Get the current network information: ip_version, hostname, auto_mode_extend
    oem_info = ibmc.oem_info
    try:
        current_network_info = get_current_network_info(ibmc)
    except Exception as e:
        log_msg = "Get current network information failed! The error info is: %s \n" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # combine public network information and private network information
    combine_info = combine_public_and_private(ibmc, public_info, current_network_info, private_info)

    # check ip_version and ip_addr
    # Setting "hostname": "test" for being compatible with previous function--set_ibmc_ip
    network_info = {
        IP_VERSION: combine_info.get(IP_VERSION), IPV4_ADDR: combine_info.get(IPV4_ADDR),
        IPV6_ADDR: combine_info.get(IPV6_ADDR), IPV6_GATEWAY: combine_info.get(IPV6_GATEWAY), HOSTNAME: "test"
    }
    check_result = check_information(ibmc, network_info, current_network_info)
    if not check_result.get(RESULT):
        return check_result

    # Verify the legality of the IPv4 address, IPv6 address and IPv6 gateway
    verify_result = validate_ip_address(ibmc, ipv4_address_list=combine_info.get(IPV4_ADDR),
                                        ipv6_address_list=combine_info.get(IPV6_ADDR),
                                        ipv6_gateway=combine_info.get(IPV6_GATEWAY))
    if not verify_result.get(RESULT):
        return verify_result

    # assemble parameters to payload and oem
    payload = assemble_to_payload(ibmc, combine_info, current_network_info)

    try:
        oem_dict = assemble_to_oem(ibmc, combine_info)
    except ValueError as e:
        log_msg = "Property value not in list: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    if not payload and not oem_dict and not combine_info.get(IP_VERSION):
        log_msg = 'There is no network information to be modified for the current host.'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    if oem_dict:
        payload["Oem"] = {oem_info: oem_dict}
    if combine_info.get(IP_VERSION):
        combine_info[IP_VERSION] = IP_DICT.get(str(combine_info.get(IP_VERSION)).lower())

    # if address information hasn't been set, then it only takes one patch
    if payload.get("IPv4Addresses") or payload.get("IPv6Addresses") or payload.get("IPv6DefaultGateway"):
        ret = set_ip_result(ibmc, payload, combine_info.get(IP_VERSION), current_network_info.get("curr_ip_version"))
    else:
        if combine_info.get(IP_VERSION):
            oem_dict[IP_VERSION_REDFISH] = combine_info.get(IP_VERSION)
            # if oem_dict was None before, it won't be added to payload, so it must be updated.
            payload["Oem"] = {oem_info: oem_dict}
        ret = set_ibmc_ip_request(ibmc, payload, log_massage="ethernet interface")

    return ret


def get_current_network_info(ibmc):
    """
    Function: get current network information
    """
    oem_info = ibmc.oem_info
    request_result_json = get_ibmc_ip_request(ibmc)
    current_network_info = {
        "auto_mode_extend_enable": False,
        "curr_ip_version": request_result_json["Oem"][oem_info][IP_VERSION_REDFISH],
        HOSTNAME: request_result_json[HOST_NAME]
    }
    if request_result_json["Oem"][oem_info].get("AutoModeExtend"):
        current_network_info["auto_mode_extend_enable"] = True
    return current_network_info


def combine_public_and_private(ibmc, public_info, current_network_info, private_info=None):
    """
    Function: combine public network information and private network information

    Returns: combined information
    """
    if private_info is None:
        private_info = {}
    combine_info = {
        IP_VERSION: private_info.get(IP_VERSION)
        if private_info.get(IP_VERSION) is not None
        else public_info.get(IP_VERSION)
    }
    # if the private information is not None, then use private parameters, otherwise use public parameters
    # combine to ipv4_addr
    ipv4_subnet_mask = public_info.get("ipv4_subnet_mask")
    ipv4_gateway = public_info.get("ipv4_gateway")
    ipv4_address_origin = public_info.get("ipv4_address_origin")
    combine_info[IPV4_ADDR] = combine_ipv4_addr_list(private_info.get(IPV4_ADDR),
                                                     public_subnet_mask=ipv4_subnet_mask,
                                                     public_gateway=ipv4_gateway,
                                                     public_address_origin=ipv4_address_origin)
    # combine to ipv6_addr
    ipv6_prefix_length = public_info.get("ipv6_prefix_length")
    ipv6_address_origin = public_info.get("ipv6_address_origin")
    combine_info.update(combine_ipv6_addr_list(private_info.get(IPV6_ADDR),
                                               public_prefix_length=ipv6_prefix_length,
                                               public_address_origin=ipv6_address_origin,
                                               public_gateway=public_info.get(
                                                   IPV6_GATEWAY),
                                               private_gateway=private_info.get(
                                                   IPV6_GATEWAY)))
    combine_info[HOSTNAME] = private_info.get(HOSTNAME)
    combine_info[VLAN] = private_info.get(VLAN) \
        if private_info.get(VLAN) is not None \
        else public_info.get(VLAN)
    combine_info.update(combine_to_dns(public_info, private_info))
    combine_info.update(combine_to_oem(ibmc, public_info, current_network_info, private_info))

    return combine_info


def combine_to_dns(public_info, private_info=None):
    """
    Function: combine dns_address_origin, name_servers, domain_name to dns_dict
    """
    if private_info is None:
        private_info = {}
    dns_dict = {}
    private_dns_address_origin = private_info.get(DNS_ADDRESS_ORIGIN)
    public_dns_address_origin = public_info.get(DNS_ADDRESS_ORIGIN)
    dns_dict[DNS_ADDRESS_ORIGIN] = private_dns_address_origin
    dns_dict[DOMAIN_NAME] = private_info.get(DOMAIN_NAME)
    dns_dict[NAME_SERVERS] = private_info.get(NAME_SERVERS)
    if str(private_dns_address_origin).lower() != "ipv4" \
            and str(private_dns_address_origin).lower() != "ipv6":
        if dns_dict.get(DOMAIN_NAME) is None:
            dns_dict[DOMAIN_NAME] = public_info.get(DOMAIN_NAME)
        if dns_dict.get(NAME_SERVERS) is None:
            dns_dict[NAME_SERVERS] = public_info.get(NAME_SERVERS)
    if (private_dns_address_origin is None) and \
            (str(public_dns_address_origin).lower() != "ipv4") and \
            (str(public_dns_address_origin).lower() != "ipv6"):
        dns_dict[DNS_ADDRESS_ORIGIN] = public_dns_address_origin
    return dns_dict


def combine_to_oem(ibmc, public_info, current_network_info, private_info=None):
    """
    Function: combine oem information
    """
    if private_info is None:
        private_info = {}
    combine_oem = {
        NETWORK_PORT_MODE: private_info.get(NETWORK_PORT_MODE)
        if private_info.get(NETWORK_PORT_MODE) is not None
        else public_info.get(NETWORK_PORT_MODE),
        MANAGEMENT_NETWORK_PORT: private_info.get(MANAGEMENT_NETWORK_PORT)
        if private_info.get(MANAGEMENT_NETWORK_PORT) is not None
        else public_info.get(MANAGEMENT_NETWORK_PORT),
        ADAPTIVE_PORT: private_info.get(ADAPTIVE_PORT)
        if private_info.get(ADAPTIVE_PORT) is not None
        else public_info.get(ADAPTIVE_PORT),
    }

    if not current_network_info.get("auto_mode_extend_enable") \
            and (private_info.get(AUTO_MODE_EXTEND) or public_info.get(AUTO_MODE_EXTEND)):
        ibmc.log_warn("The ibmc version of this server does not support Auto Mode Extensions. ")
    if current_network_info.get("auto_mode_extend_enable"):
        combine_oem[AUTO_MODE_EXTEND] = private_info.get(AUTO_MODE_EXTEND) \
            if private_info.get(AUTO_MODE_EXTEND) is not None \
            else public_info.get(AUTO_MODE_EXTEND)
    return combine_oem


def combine_ipv4_addr_list(ipv4_addresses, public_subnet_mask, public_gateway, public_address_origin):
    """
    Function: Combine public and private parameters to ipv4 address list.
    """
    ipv4_addr_ret = []

    # if private ipv4 addresses information haven't been set
    if not ipv4_addresses:
        ipv4_addr_dict = combine_ipv4(public_subnet_mask, public_gateway, public_address_origin)
        if ipv4_addr_dict:
            ipv4_addr_ret.append(ipv4_addr_dict)
        return ipv4_addr_ret

    # if private ipv4 addresses information have been set
    for ipv4_address in ipv4_addresses:
        private_address_origin = ipv4_address.get("address_origin")
        # If the fetching mode is dynamic, no public parameters are required
        address_origin = private_address_origin
        gateway = ipv4_address.get("gateway")
        subnet_mask = ipv4_address.get("subnet_mask")
        if str(private_address_origin).lower() != "dhcp":
            if subnet_mask is None:
                subnet_mask = public_subnet_mask
            if gateway is None:
                gateway = public_gateway
        if private_address_origin is None and str(public_address_origin).lower() != "dhcp":
            address_origin = public_address_origin
        ipv4_addr_dict = combine_ipv4(subnet_mask, gateway, address_origin, ipv4_address.get("address"))
        if ipv4_addr_dict:
            ipv4_addr_ret.append(ipv4_addr_dict)
    return ipv4_addr_ret


def combine_ipv4(subnet_mask, gateway, address_origin, address=None):
    """
    Function: To be compatible with the judgement condition of check_information function,
              the non-empty content is stored in the dictionary in advance.
    """
    ipv4_addr_dict = {}
    if address:
        ipv4_addr_dict["address"] = address
    if subnet_mask:
        ipv4_addr_dict["subnet_mask"] = subnet_mask
    if gateway:
        ipv4_addr_dict["gateway"] = gateway
    if address_origin:
        ipv4_addr_dict["address_origin"] = address_origin
    return ipv4_addr_dict


def combine_ipv6_addr_list(ipv6_addresses, public_prefix_length, public_address_origin,
                           public_gateway, private_gateway):
    """
    Function: Combine public and private parameters to ipv4 address list.
    """
    ipv6_addr_ret = []
    # if private ipv6 addresses information haven't been set
    if not ipv6_addresses:
        ipv6_addr_dict = combine_ipv6(public_prefix_length, public_address_origin)
        if ipv6_addr_dict:
            ipv6_addr_ret.append(ipv6_addr_dict)
        return {IPV6_ADDR: ipv6_addr_ret, IPV6_GATEWAY: public_gateway}

    # if private ipv6 addresses information have been set
    gateway = private_gateway
    for ipv6_address in ipv6_addresses:
        # If the fetching mode is dynamic, no public parameters are required
        private_address_origin = ipv6_address.get("address_origin")
        prefix_length = ipv6_address.get("prefix_length")
        address_origin = ipv6_address.get("address_origin")
        if str(private_address_origin).lower() != "dhcpv6":
            if prefix_length is None:
                prefix_length = public_prefix_length
            if gateway is None:
                gateway = public_gateway
        if private_address_origin is None and str(public_address_origin).lower() != "dhcpv6":
            address_origin = public_address_origin
        ipv6_addr_dict = combine_ipv6(prefix_length, address_origin, ipv6_address.get("address"))
        if ipv6_addr_dict:
            ipv6_addr_ret.append(ipv6_addr_dict)
    return {IPV6_ADDR: ipv6_addr_ret, IPV6_GATEWAY: gateway}


def combine_ipv6(prefix_length, address_origin, address=None):
    """
    Function: To be compatible with the judgement condition of check_information function,
              the non-empty content is stored in the dictionary in advance.
    """
    ipv6_addr_dict = {}
    if address:
        ipv6_addr_dict["address"] = address
    if prefix_length is not None:
        ipv6_addr_dict["prefix_length"] = prefix_length
    if address_origin:
        ipv6_addr_dict["address_origin"] = address_origin
    return ipv6_addr_dict


def assemble_to_payload(ibmc, combine_info, current_network_info):
    """
    Function: assemble parameters to payload

    Returns: payload
    """
    payload = {}
    if combine_info.get(HOSTNAME):
        payload[HOST_NAME] = combine_info.get(HOSTNAME)
    if combine_info.get(DOMAIN_NAME) is not None:
        # Domain name can be null, FQDN can be "host0."
        domain_name = combine_info.get(DOMAIN_NAME)
        if payload.get(HOST_NAME) is not None:
            payload[FQDN] = payload.get(HOST_NAME) + '.' + domain_name
        elif current_network_info.get(HOSTNAME) is not None:
            payload[FQDN] = current_network_info.get(HOSTNAME) + "." + domain_name
        else:
            payload[FQDN] = domain_name
            log_msg = "The host name is empty. Setting the domain name assigns \
                      the first field of the domain name to the host name."
            ibmc.log_warn(log_msg)
    if combine_info.get(VLAN):
        vlan_format = convert_vlan(combine_info.get(VLAN))
        if vlan_format:
            payload["VLAN"] = vlan_format
    if combine_info.get(NAME_SERVERS):
        name_servers_temp = []
        for name_server in combine_info.get(NAME_SERVERS):
            if name_server is not None and name_server != 'None':
                # Name server can be null. And when the type of list element is string, ansible will convert None(
                # type NoneType) to 'None'(type string).
                name_servers_temp.append(name_server)
        if name_servers_temp:
            payload["NameServers"] = name_servers_temp
    if combine_info.get(IPV4_ADDR):
        ipv4_addr_format = convert_ipv4_addr(combine_info.get(IPV4_ADDR))
        if ipv4_addr_format:
            payload['IPv4Addresses'] = ipv4_addr_format
    if combine_info.get(IPV6_ADDR):
        ipv6_addr_format = convert_ipv6_addr(combine_info.get(IPV6_ADDR))
        if ipv6_addr_format:
            payload['IPv6Addresses'] = ipv6_addr_format
    if combine_info.get(IPV6_GATEWAY):
        payload['IPv6DefaultGateway'] = combine_info.get(IPV6_GATEWAY)

    return payload


def assemble_to_oem(ibmc, combine_info):
    """
    Function: Extract oem information to oem_dict from combine information

    Returns: oem_dict
    """
    oem_dict = {}
    # Firstly check if it's in the dictionary, then convert it to standard format
    if combine_info.get(NETWORK_PORT_MODE):
        network_port_mode = combine_info.get(NETWORK_PORT_MODE)
        if str(network_port_mode).lower() not in MODE_DICT:
            raise ValueError("The network port mode is incorrect, it should be 'Fixed' or 'Automatic'.")
        oem_dict["NetworkPortMode"] = MODE_DICT.get(str(network_port_mode).lower())
    if combine_info.get(DNS_ADDRESS_ORIGIN):
        dns_address_origin = combine_info.get(DNS_ADDRESS_ORIGIN)
        if str(dns_address_origin).lower() not in DNS_ADDRESS_ORIGIN_DICT:
            raise ValueError("The DNS address origin is incorrect, it should be 'IPv4', 'IPv6' or 'Static'.")
        oem_dict["DNSAddressOrigin"] = DNS_ADDRESS_ORIGIN_DICT.get(str(dns_address_origin).lower())
    if combine_info.get(MANAGEMENT_NETWORK_PORT):
        mnp_format = convert_management_network_port(combine_info.get(MANAGEMENT_NETWORK_PORT))
        if mnp_format:
            oem_dict["ManagementNetworkPort"] = mnp_format
    if combine_info.get(ADAPTIVE_PORT):
        ap_format = convert_adaptive_port(ibmc, combine_info.get(ADAPTIVE_PORT))
        if ap_format:
            oem_dict["AdaptivePort"] = ap_format
    if combine_info.get(AUTO_MODE_EXTEND):
        ame_format = convert_auto_mode_extend(ibmc, combine_info.get(AUTO_MODE_EXTEND))
        if ame_format:
            oem_dict["AutoModeExtend"] = ame_format
    return oem_dict


def convert_vlan(vlan):
    """
    Function: Convert vlan format

    Args:
        vlan: dict
    """
    vlan_ret = {}
    if vlan.get("vlan_enable") is not None:
        vlan_ret["VLANEnable"] = vlan["vlan_enable"]
    if vlan.get("vlan_id") is not None:
        vlan_ret["VLANId"] = vlan["vlan_id"]
    return vlan_ret


def convert_management_network_port(management_network_port):
    """
    Function: Convert management_network_port format

    Args:
        management_network_port: dict
    """
    mnp_ret = {}
    if management_network_port.get("type"):
        mnp_type = management_network_port["type"]
        if str(mnp_type).lower() not in TYPE_DICT:
            raise ValueError("The management network port type is incorrect, it should be 'Dedicated', 'Aggregation', "
                             "'LOM', 'ExternalPCIe', 'LOM2' or 'OCP'.")
        mnp_ret["Type"] = TYPE_DICT.get(str(mnp_type).lower())

    if management_network_port.get("port_number") is not None:
        mnp_ret["PortNumber"] = management_network_port["port_number"]
    return mnp_ret


def convert_adaptive_port(ibmc, adaptive_port_list):
    """
    Function: Convert adaptive_port format

    Args:
        ibmc : Class that contains basic information about iBMC
        adaptive_port_list: list
    """
    ap_ret_list = []
    for adaptive_port_dict in adaptive_port_list:
        ap_ret_dict = {}
        try:
            port_dict = convert_management_network_port(adaptive_port_dict)
        except ValueError as e:
            ibmc.log_error("'The adaptive port type is incorrect, it should be 'Dedicated', 'Aggregation', "
                             "'LOM', 'ExternalPCIe', 'LOM2' or 'OCP'. ")
            raise e
        ap_ret_dict.update(port_dict)
        if adaptive_port_dict.get("adaptive_flag") is not None:
            ap_ret_dict["AdaptiveFlag"] = adaptive_port_dict["adaptive_flag"]
        if ap_ret_dict:
            ap_ret_list.append(ap_ret_dict)
    return ap_ret_list


def convert_auto_mode_extend(ibmc, auto_mode_extend):
    """
    Function: Convert auto_mode_extend format

    Args:
        ibmc : Class that contains basic information about iBMC
        auto_mode_extend: dict
    """
    ame_ret = {}
    if auto_mode_extend.get("high_priority_mode") is not None:
        ame_ret["HighPriorityMode"] = auto_mode_extend["high_priority_mode"]
    hpp_ret_list = []
    if auto_mode_extend.get("high_priority_port"):
        high_priority_port_list = auto_mode_extend["high_priority_port"]
        for high_priority_port in high_priority_port_list:
            # high_priority_port has the same format as management_network_port
            try:
                hpp_ret_dict = convert_management_network_port(high_priority_port)
            except ValueError as e:
                ibmc.log_error("The high priority port type is incorrect, it should be 'Dedicated', 'Aggregation', "
                               "'LOM', 'ExternalPCIe', 'LOM2' or 'OCP'. ")
                raise e
            if hpp_ret_dict:
                hpp_ret_list.append(hpp_ret_dict)
    if hpp_ret_list:
        ame_ret["HighPriorityPort"] = hpp_ret_list
    return ame_ret
