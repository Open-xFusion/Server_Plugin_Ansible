#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2023 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os
import requests

from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import IBMC_REPORT_PATH
from ibmc_ansible.utils import set_result


def set_web_session_timeout(ibmc, web_session_timeout_minutes):
    """
    Function:
        Set web session timeout
    Args:
        ibmc : Class that contains basic information about iBMC
        web_session_timeout_minutes : The timeout of a web session in minutes
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    """
    ibmc.log_info("Start to set web session timeout...")
    payload = {"Oem": {ibmc.oem_info: {"WebSessionTimeoutMinutes": web_session_timeout_minutes}}}
    ret = set_web_session_timeout_request(ibmc, payload)
    return ret


def set_web_session_timeout_request(ibmc, payload):
    """
    Function:
        send request to set web session timeout
    Args:
        ibmc : Class that contains basic information about iBMC
        payload : request body
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         Exception
    """

    ret = {'result': False, 'msg': ''}

    url = os.path.join(ibmc.root_uri, "SessionService")
    token = ibmc.get_token()
    e_tag = ibmc.get_etag(url)
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': e_tag}

    try:
        request_result = ibmc.request('PATCH', resource=url, headers=headers,
                                      data=payload, tmout=10)
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Set web session timeout successfully!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Set web session timeout failed! The error code is: %s, The error info is: %s." % \
                      (str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        error_msg = "Set web session timeout failed! The error info is: %s \n" % str(e)
        ibmc.log_error(error_msg)
        raise requests.exceptions.RequestException(error_msg)

    return ret


def get_web_session_timeout(ibmc):
    """
    Function:
        Get web session timeout
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    """
    ibmc.log_info("Start to get web session timeout...")

    ret = {'result': False, 'msg': ''}

    # File to save web session timeout
    result_file = os.path.join(IBMC_REPORT_PATH, "web_session_timeout",
                               "%s_web_session_timeout.json" % str(ibmc.ip))

    request_result_json = get_web_session_timeout_request(ibmc)
    web_session_timeout_minutes = request_result_json["Oem"][ibmc.oem_info]["WebSessionTimeoutMinutes"]
    result = {
        "WebSessionTimeoutMinutes": web_session_timeout_minutes
    }
    write_result(ibmc, result_file, result)

    ret['result'] = True
    ret['msg'] = "Get web session timeout successful! Web session timeout is: %s minutes. " \
                 "For more detail information please refer to %s." % (web_session_timeout_minutes, result_file)
    ibmc.log_info("Get web session timeout successful!")

    return ret


def get_web_session_timeout_request(ibmc):
    """
    Function:
        send request to get web session timeout
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         Exception
    """

    token = ibmc.get_token()
    url = os.path.join(ibmc.root_uri, "SessionService")
    headers = {'X-Auth-Token': token}
    payload = {}

    try:
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=10)
        request_code = request_result.status_code
        if request_code == 200:
            request_result_json = request_result.json()
        else:
            error = "Get web session timeout failed! The error code is: %s. The error info is: %s" \
                    % (str(request_code), str(request_result.json()))
            ibmc.log_error(error)
            raise Exception(error)
    except Exception as e:
        error = "Get web session timeout failed! The error info is: %s" % str(e)
        ibmc.log_error(error)
        raise requests.exceptions.RequestException(error)

    return request_result_json
