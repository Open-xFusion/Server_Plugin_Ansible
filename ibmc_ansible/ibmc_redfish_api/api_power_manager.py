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

from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import IBMC_REPORT_PATH
from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import RESULT, MSG


def manage_power(ibmc, command):
    """
    Args:
            ibmc               (class)
            command            (str): poweron or poweroff the server
    Returns:
        rets {'result':'','msg':''}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    uri = "%s/Actions/ComputerSystem.Reset" % ibmc.system_uri
    rets = {RESULT: True, MSG: ''}
    power_cmd_dict = {
        "poweron": 'On',
        "poweroff": 'ForceOff',
        "forcerestart": 'ForceRestart',
        "gracefulshutdown": 'GracefulShutdown',
        "forcepowercycle": 'ForcePowerCycle',
        "nmi": 'Nmi'
    }

    if command.lower() not in power_cmd_dict.keys():
        log_msg = "unsupport for this command :%s" % command
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    payload = {'ResetType': power_cmd_dict[command.lower()]}
    try:
        r = ibmc.request("POST", resource=uri, headers=headers, data=payload)
    except Exception as e:
        ibmc.log_info("set power command exception!  command is:%s  exception is:%s" % (command, str(e)))
        raise e
    try:
        result = r.status_code
        if result == 200:
            log_msg = "set system %s successful!" % str(command)
            set_result(ibmc.log_info, log_msg, True, rets)
        else:
            log_msg = "set system %s failed! error code is:%s" % (command, str(r.status_code))
            set_result(ibmc.log_error, log_msg, False, rets)
    except Exception as e:
        ibmc.log_error("set system %s  parse response exception ! exception is : %s" % (command, str(e)))
        raise e
    return rets


def get_power_status(ibmc):
    """
    Args:
            ibmc            (class):
    Returns:
        None
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    uri = ibmc.system_uri
    rets = {RESULT: True, MSG: ''}
    payload = {}
    try:
        response = ibmc.request("GET", resource=uri, headers=headers, data=payload)
    except Exception as e:
        ibmc.log_error("send get power state exception; exception is: %s" % (str(e)))
        raise e
    try:
        if response.status_code == 200:
            data = response.json()
            power_state = data[u'PowerState']
            
            if hasattr(ibmc, 'is_write_file') and ibmc.is_write_file:
                fw_info_dic = {'PowerState' : power_state}
                filename = os.path.join(IBMC_REPORT_PATH,
                                        "power_status/%s_power_status.json" % str(ibmc.ip))
                write_result(ibmc, filename, fw_info_dic)
    
            log_msg = "get system power state successful! power status is :%s" % power_state
            set_result(ibmc.log_info, log_msg, True, rets)
            return rets
        else:
            ibmc.log_error(" get system power state failed!")
            raise Exception(
                "get power state failed , error code exception,error code is  %s" % str(response.status_code))
    except Exception as e:
        ibmc.log_error("parse response exception %s" % (str(e)))
        raise e
