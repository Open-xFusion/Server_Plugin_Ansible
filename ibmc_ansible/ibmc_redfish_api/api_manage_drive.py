#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2023-2023 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import requests


from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import RESULT, MSG


FIRMWARE_STATUS = ["UnconfiguredGood", "JBOD", "Online", "Offline"]
OEM = "Oem"


def drive_id_verify(ibmc, drives_info):
    """
        Function:
            verify reason ability of user set drive
        Args:
            ibmc : Class that contains basic information about iBMC
            drives_info : user set drive information
        Returns:
            ret : a dict of task result
                "result": True or False
                "msg": description for success or failure
        Raises:
            None
        Date: 2023/12/7 22:07
    """
    ret = {RESULT: True, MSG: ''}
    drives = drives_info.get("drives")
    if not isinstance(drives, list):
        log_msg = 'The drives info is incorrect, please set it in the modify_drive.yml'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    if len(drives) < 1:
        log_msg = 'The drives is null, please set it in the modify_drive.yml file'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    return ret


def get_all_driver_id(ibmc):
    """
        Function:
            Get all driver id
        Args:
            ibmc : Class that contains basic information about iBMC
        Returns:
            all_drives_id : all drive id, Example: [HDDPlaneDisk0,HDDPlaneDisk1]
        Raises:
            Get driver id failed!
        Date: 2023/12/7 20:52
    """
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token
    # URL of the NTP service
    url = "%s/Drives" % ibmc.chassis_uri
    # Initialize headers
    headers = {'X-Auth-Token': token}
    # Initialize payload
    payload = {}

    try:
        # Obtain the NTP configuration resource information through the GET method
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            msg = "Get drives info failed, the error code is: %s, " \
                  "The error info is: %s \n" % (str(request_code), str(request_result.json()))
            ibmc.log_error(msg)
            raise Exception(msg)
    except Exception as e:
        msg = "Get drives info failed, the error code is: %s, " \
              "The error info is: %s \n" % (str(request_code), str(request_result.json()))
        ibmc.log_error(msg)
        raise requests.exceptions.RequestException(msg)

    request_result_json = request_result.json()
    all_drives_id = []
    try:
        for members in request_result_json.get("Members"):
            drives_id_url = members.get("@odata.id")
            all_drives_id.append(str(drives_id_url).split("/")[-1])
    except Exception as e:
        ibmc.log_error("Get drivers id failed! The error info is: %s \n" % str(e))
        raise e
    return all_drives_id


def verify_drives_id(ibmc, drive, all_disk_drives_id):
    """
        Function:
            verify reason ability of drive id
        Args:
            ibmc : Class that contains basic information about iBMC
            drive: user set drive
            all_disk_drives_id : user set drives info
        Returns:
            ret : a dict of task result
                "result": True or False
                "msg": description for success or failure
        Raises:
            None
        Date: 2023/12/7 22:07
    """
    ret = {RESULT: True, MSG: ''}
    drive_id = drive.get("drive_id")
    if not drive_id:
        log_msg = "The drive id cannot be empty, please set it in the modify_drive.yml"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    if drive_id not in all_disk_drives_id:
        log_msg = "The drive id: %s does not exist" % drive_id
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    return ret


def get_firmware_status(ibmc, drive):
    """
       Function:
           Get user set firmware_status
       Args:
           ibmc : Class that contains basic information about iBMC
           drive : User-set firmware_status
       Returns:
           ret : a dict of task result
               "result": True or False
               "msg": description for success or failure
       Raises:
           None
       Date: 2023/12/7 18:04
    """
    ret = {RESULT: True, MSG: ''}
    firmware_status = drive.get("firmware_status")
    if firmware_status is not None:
        try:
            if firmware_status not in FIRMWARE_STATUS:
                log_msg = "Invalid status, the status is %s" % str(
                    firmware_status)
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
        except Exception as e:
            ibmc.log_error("Invalid status, the status is %s" % str(e))
            raise ValueError(
                "Invalid status, the firmware is %s" % str(e)) from e
        ret[MSG] = firmware_status
    else:
        log_msg = "Firmware status cannot be empty, please set it in the modify_drive.yml"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    return ret


def get_drives_modify_oem(ibmc, drive):
    """
       Function:
           Get oem information for modify drive configuration
       Args:
           ibmc : Class that contains basic information about iBMC
           drive : User-set drive information
       Returns:
           ret : a dict of task result
               "result": True or False
               "msg": description for success or failure
       Raises:
           None
       Date: 2023/12/7 18:04
    """
    ret = {RESULT: True, MSG: ''}
    oem = {}
    firmware_status = get_firmware_status(ibmc, drive)
    if firmware_status.get(RESULT) is False:
        return firmware_status
    elif firmware_status.get(RESULT) and firmware_status.get(MSG) != '':
        oem["FirmwareStatus"] = firmware_status.get(MSG)
    ret[MSG] = oem
    return ret


def modify_drives_request(ibmc, payload, drives_id):
    """
        Function:
            Send modify drives firmware_status request
        Args:
            ibmc : Class that contains basic information about iBMC
            payload : Request message body
            drives_id : User-set drives controller ID
        Returns:
            ret : a dict of task result
                "result": True or False
                "msg": description for success or failure
        Raises:
            None
        Date: 2023/12/7 18:55
    """
    # init result
    ret = {RESULT: True, MSG: ''}
    # URL of the drives
    url = "%s/Drives/%s" % (ibmc.chassis_uri, drives_id)
    # Obtain token
    token = ibmc.bmc_token
    # Obtain etag
    etag = ibmc.get_etag(url)
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}

    try:
        request_result = ibmc.request('PATCH', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Modify drive: %s configuration successfully." % drives_id
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Failed to modify drives: %s, The error code is: %s, the error info is: %s." % \
                      (drives_id, str(request_code),
                       str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "Failed to modify drives : %s, the error info is: %s." % (
            drives_id, str(e))
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def modify_drive_status(ibmc, drives_info):
    """
        Function:
            modify drive mode status
        Args:
            ibmc : Class that contains basic information about iBMC
            drives_info : User-set drives information
        Returns:
            ret : a dict of task result
                "result": True or False
                "msg": description for success or failure
        Raises:
            None
        Date: 2023/12/7 18:04
    """
    ibmc.log_info("Start modify drives configuration...")
    # check drives_id
    ret = drive_id_verify(ibmc, drives_info)
    if not ret.get(RESULT):
        return ret

    # Get all drives_id ID
    all_drives_id = get_all_driver_id(ibmc)
    ibmc.log_info("Get all drives_id ID: %s..." % all_drives_id)
    drives = drives_info.get("drives")

    # Verify User-set drives controller id and drives id
    for drive in drives:
        # Obtain User-set drive controller ID
        ret = verify_drives_id(ibmc, drive, all_drives_id)
        if not ret.get(RESULT):
            return ret

    # init result
    result_list = []
    flag = True
    oem_info = ibmc.oem_info
    for drive in drives:
        payload = {}
        drives_id = drive.get("drive_id")
        oem = get_drives_modify_oem(ibmc, drive)
        if not oem.get(RESULT):
            return oem
        payload[OEM] = {oem_info: oem.get(MSG)}
        # Get modify drives result
        result = modify_drives_request(ibmc, payload, drives_id)
        if result.get(RESULT) is False:
            flag = False
        result_list.append(result)

    if flag is False:
        log_msg = "Failed to modify drive configuration, the result is: %s" % str(
            result_list)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    log_msg = "Modify drive configuration successfully, the result is: %s" % str(
        result_list)
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret
