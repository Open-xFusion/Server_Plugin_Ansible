#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import csv
import json
import logging
import os
import re
import subprocess
import stat

from ibmc_ansible.logger_permission import SetLogPermission

try:
    import ConfigParser as cp
except ImportError:
    import configparser as cp
try:
    USER = os.popen('/usr/bin/whoami').read().split("\n")[0]
except Exception as e:
    logging.error("Unable to get current user name, the error as %s", str(e))
    raise

IBMC_LOG_PATH = "/home/%s/ansible_ibmc/log" % USER
IBMC_REPORT_PATH = "/home/%s/ansible_ibmc/report" % USER
IBMC_EXCU_PATH = "/home/ibmc_ansible"
BASIC_PATH = "/home/%s/ansible_ibmc" % USER
MSG_FORMAT = "%s -- %s"

# Switch type
SERVERSWITYPE = 2
# Hmm type
SERVERHMMTYPE = 1
# Server type
SERVERTYPE = 0

RESULT = "result"
MSG = "msg"
REQUIRED = "required"
TYPE = "type"
STR = "str"
NO_LOG = "no_log"
LIST = "list"
DICT = "dict"
BOOL = "bool"
INT = "int"
ELEMENTS = "elements"
OPTIONS = "options"
IBMC_IP = "ibmc_ip"
DOUBLE_COLON = "::"
ODATA_ID = "@odata.id"


def set_result(log_function, msg, result, ret):
    """

    Function:
         set result
    Args:
              log_function              (function):
              result       (bool):
              msg                  (str):
              ret               (dic):
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 2019/10/9 20:30
    """
    log_function(msg)
    ret['result'] = result
    ret['msg'] = msg


def ansible_ibmc_run_module(function_callback, ansible_module, log, report):
    """

    Function:
         write report _
    Args:
              function_callback              (function):   module function
              ansible_module       (class):
              log                  (class):
              report               (class):
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 2019/10/9 20:30
    """
    try:
        ret = function_callback(ansible_module)
        if ret[RESULT] is True:
            report.info(MSG_FORMAT % (str(ansible_module.params.get(IBMC_IP)), ret[MSG]))
            ansible_module.exit_json(msg=ret[MSG])
        else:
            report.error(MSG_FORMAT % (str(ansible_module.params.get(IBMC_IP)), ret[MSG]))
            ansible_module.fail_json(msg=ret[MSG])
    except Exception as ex:
        log.error(MSG_FORMAT % (str(ansible_module.params.get(IBMC_IP)), str(ex)))
        report.error(MSG_FORMAT % (str(ansible_module.params.get(IBMC_IP)), str(ex)))
        ansible_module.fail_json(msg=str(ex))


def ansible_get_loger(log_file, report_file, logger_name):
    """
    Args:
            logFile            (str):
            reportFile         (str):
            loggerName         (str):
    Returns:
        log
        report
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """

    log_hander = SetLogPermission(log_file, max_bytes=1024 * 1024, backup_count=100)
    fmt = logging.Formatter("[%(asctime)s %(levelname)s ]- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
    log_hander.setFormatter(fmt)
    log = logging.getLogger(logger_name)
    log.addHandler(log_hander)
    log.setLevel(logging.INFO)

    fmt = logging.Formatter("[%(asctime)s %(levelname)s ] - %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
    report_hander = SetLogPermission(report_file, max_bytes=1024 * 1024, backup_count=100)
    report_hander.setFormatter(fmt)
    report = logging.getLogger(logger_name + "report")
    report.addHandler(report_hander)
    report.setLevel(logging.INFO)
    return log, report


def write_result(ibmc, result_file, result):
    """

    Function:
        Write the result to a file
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
              result_file       (str):     result file
              result            (json):    result data
    Returns:
        None
    Raises:
        IOError
    Examples:
        None
    Author:
    Date: 2019/10/9 20:30
    """
    json_file = None
    try:
        # Create a path if the path does not exist
        result_path = os.path.dirname(result_file)
        if not os.path.exists(result_path):
            subprocess.call(["mkdir", "-p", result_path], shell=False)
            os.chmod(result_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
        # Write the results to the file as an overlay
        flags = os.O_WRONLY | os.O_CREAT
        with os.fdopen(os.open(result_file, flags, stat.S_IRUSR | stat.S_IWUSR), "w") as json_file:
            if json_file and result:
                json.dump(result, json_file, indent=4)
    except IOError as ex:
        ibmc.log_error("Failed to write result to %s, the error info is: %s" % (result_file, str(ex)))
        ibmc.report_error("Failed to write result to %s" % result_file)
        raise ex


def write_result_csv(ibmc, result_file, header_csv, result_csv):
    """

    Function:
        Write the result to a csv file
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
              result_file       (str):     result file
              header_csv        (list):    csv header
              result_csv        (list):    csv result data
    Returns:
        None
    Raises:
        IOError
    Examples:
        None
    Author:
    Date: 2020/10/9
    """
    csv_file = None
    try:
        # Create a path if the path does not exist
        result_path = os.path.dirname(result_file)
        if not os.path.exists(result_path):
            subprocess.call(["mkdir", "-p", result_path], shell=False)
            os.chmod(result_path, stat.S_IRUSR | stat.S_IWUSR)
        # Write the results to the csv file
        flags = os.O_WRONLY | os.O_CREAT
        with os.fdopen(os.open(result_file, flags, stat.S_IRUSR | stat.S_IWUSR), 'w') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(header_csv)
            csv_writer.writerow(result_csv)
    except IOError as ex:
        ibmc.log_error("Failed to write result to %s, the error info is: %s" % (result_file, str(ex)))
        ibmc.report_error("Failed to write result to %s" % result_file)
        raise ex


def validate_ipv4(ip_str):
    """

    Function:
        Verify IPv4 address
    Args:
              ip_str            (str):   IPv4 address
    Returns:
        True or False
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/8 19:39
    """
    if ip_str:
        ip_list = ip_str.split(".")
        if len(ip_list) != 4:
            return False
        try:
            for ip in ip_list:
                ip_int = int(ip)
                if ip_int < 0 or ip_int > 255:
                    return False
        except ValueError:
            return False
    return True


def validate_ipv6(ip_str):
    """

    Function:
        Verify IPv6 address
    Args:
              ip_str            (str):   IPv6 address
    Returns:
        True or False
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/8 19:56
    """
    if not ip_str:
        return True

    # Normal IPv6 format
    hex_re = re.compile(r'^:{0,1}([0-9a-fA-F]{0,4}:){0,7}[0-9a-fA-F]{0,4}:{0,1}$')
    # IPv4-compatible IPv6 format
    dotted_quad_re = re.compile(r'^:{0,1}([0-9a-fA-F]{0,4}:){2,6}(\d{1,3}\.){3}\d{1,3}$')
    if hex_re.match(ip_str):
        if ':::' in ip_str:
            return False
        if DOUBLE_COLON not in ip_str:
            halves = ip_str.split(':')
            return len(halves) == 8 and halves[0] != '' and halves[-1] != ''
        halves = ip_str.split(DOUBLE_COLON)
        if len(halves) != 2:
            return False
        if halves[0] != '' and halves[0][0] == ':':
            return False
        if halves[-1] != '' and halves[-1][-1] == ':':
            return False
        return True

    if dotted_quad_re.match(ip_str):
        if ':::' in ip_str:
            return False
        if DOUBLE_COLON not in ip_str:
            halves = ip_str.split(':')
            return len(halves) == 7 and halves[0] != ''
        halves = ip_str.split(DOUBLE_COLON)
        if len(halves) > 2:
            return False
        hex_list = ip_str.split(':')
        quads = hex_list[-1].split('.')
        for q in quads:
            if int(q) > 255 or int(q) < 0:
                return False
        return True
    return False


def validata_ipv4_in_gateway(ip, gateway, subnet_mask):
    """

    Function:
        Determine if IPv4 Address, Gateway, and Netmask match
    Args:
              ip            (str):   IPv4 address
              gateway       (str):   IPv4 gateway
              subnet_mask   (str):   IPv4 subnet_mask
    Returns:
        True or False
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/8 20:14
    """
    if ip and gateway and subnet_mask:
        ip_list = ip.split(".")
        gateway_list = gateway.split(".")
        subnet_mask_list = subnet_mask.split(".")
        try:
            for i in range(4):
                if int(ip_list[i]) & int(subnet_mask_list[i]) != int(gateway_list[i]) & int(subnet_mask_list[i]):
                    return False
        except ValueError:
            return False
    return True


def read_ssl_verify(log):
    """
    Function:
        read_ssl_verify
    Args:
        verify str
    Returns:
       None
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 11/12/2019
    """

    try:
        cfg = cp.ConfigParser()
        cfg_path = os.path.join(IBMC_EXCU_PATH, "ssl.cfg")
        cfg.read(cfg_path)
        verify = cfg.get("ssl", "verify")
        if verify is True or verify == "True":
            return True
        elif verify is False or verify == "False":
            return False
        else:
            return verify
    except Exception as ex:
        log.info("read ssl_cfg exception : %s" % str(ex))
        return True


def read_ssl_ciphers(log):
    """
    Function:
        read_ssl_ciphers
    Args:
        ciphers str
    Returns:
       None
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 11/16/2020
    """
    try:
        cfg = cp.ConfigParser()
        cfg_path = os.path.join(IBMC_EXCU_PATH, "ssl.cfg")
        cfg.read(cfg_path)
        ciphers = cfg.get("ssl", "ciphers")
        if ciphers is None:
            return ""
        else:
            return ciphers
    except Exception as ex:
        log.info("read ssl_cfg exception : %s" % str(ex))
        return ""


def read_ssl_force_tls(log):
    """
    Function:
        read_ssl_force_tls
    Args:
        verify str
    Returns:
       None
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 24/12/2019
    """

    try:
        cfg = cp.ConfigParser()
        cfg_path = os.path.join(IBMC_EXCU_PATH, "ssl.cfg")
        cfg.read(cfg_path)
        verify = cfg.get("ssl", "force_tls1_2")
        if verify is True or verify == "True":
            return True
        elif verify is False or verify == "False":
            return False
        else:
            return True
    except Exception as ex:
        log.info("read ssl_cfg exception : %s" % str(ex))
        return True


def set_ssl_cfg(verify, force_tls1_2, ciphers, log):
    """
    Function:
        set ssl cfg
    Args:
        verify str
    Returns:
       None
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 11/12/2019
    """
    cfg_path = os.path.join(IBMC_EXCU_PATH, "ssl.cfg")
    try:
        if ciphers is None:
            _ciphers = ''
        else:
            _ciphers = ciphers
        with open(cfg_path, "r+") as file:
            file.truncate()
            file.seek(0)
            file.write("[ssl]\nverify = %s\nforce_tls1_2 = %s\nciphers = %s" % (
                str(verify), str(force_tls1_2), str(_ciphers)))
            log.info("set ssl_cfg sucessful")
            return True
    except Exception as ex:
        log.error("set ssl_cfg failed, exception is : %s" % str(ex))
    return False


def check_server_type(ibmc):
    """
    Function:
        check serverType:

    Args:
         ibmc (str):   IbmcBaseConnect Object
    Returns:
            1: Hmm type
            2: Switch type
            0: Server type
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 10/10/2020
    """
    serverid = ibmc.chassis_uri.split('/')[-1].lower()
    if "hmm" in serverid:
        return 1
    elif "swi" in serverid:
        return 2
    else:
        return 0


def is_support_server(ibmc, server_type):
    """
    Function:

    Args:
        ibmc (str):   IbmcBaseConnect Object
        server_type:   SERVERTYPE,
                SERVERSWITYPE,
                SERVERHMMTYPE
    Returns:
            "result":False
            "msg": 'The function is not supported!'
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 10/10/2020
    """
    ret = {RESULT: False, MSG: ''}
    type_code = check_server_type(ibmc)
    if type_code == server_type:
        ret[RESULT] = True
    else:
        ibmc.log_error("The function is not supported!")
        ret[RESULT] = False
        ret[MSG] = "The function is not supported!"
    return ret


def remote_file_path(file_path, module):
    """
    Function:
        get file name on remote file server
    Args:
        module : information from yml
        file_path: User-configured remote file server path
    Returns:
        file_path: Path of the combined remote file server
    Raises:
        None
    Date: 2021/6/7 20:30
    """
    # File server type
    file_server = ("sftp", "https", "nfs", "cifs", "scp")
    if not file_path:
        msg = "Remote file path cannot be empty. \n"
        raise Exception(msg)

    protocol_and_server_path = file_path.split("://")
    # If it cannot be divided into two parts, The remote file path format is incorrect.
    if len(protocol_and_server_path) != 2:
        msg = "Invalid remote file path. \n"
        raise Exception(msg)

    protocol, server_path = protocol_and_server_path
    protocol = protocol.lower()
    if protocol not in file_server:
        msg = "The protocol error, please choose from [sftp, https, nfs, cifs, scp] \n"
        raise Exception(msg)

    if module.params.get("file_server_user") and module.params.get(
            "file_server_pswd"):
        file_path = "%s://%s:%s@%s" % \
                    (protocol, module.params.get("file_server_user"),
                     module.params.get("file_server_pswd"), server_path)
    return file_path
