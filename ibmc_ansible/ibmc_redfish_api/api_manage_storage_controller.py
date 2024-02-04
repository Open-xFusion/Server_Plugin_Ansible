#!/usr/bin/python
# -*- coding: UTF-8 -*-
import requests

# Copyright (C) 2023-2023 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import RESULT, MSG

WORK_MODE = ["RAID", "JBOD"]

STORAGE_ID = "storage_id"
MESSAGES = "Messages"
OEM = "Oem"
MODE = "mode"
JBOD_STATE = "JBOD_state"


def modify_storage_controller(ibmc, storage_controller_info):
    """
    Function:
        Modify storage configuration
    Args:
        ibmc : Class that contains basic information about iBMC
        storage_controller_info : User-set storage controller information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2023/12/8 18:04
    """
    ibmc.log_info("Start modify storage controller configuration...")

    storage_controllers = storage_controller_info.get("storage_controllers")
    verify_ret = verify_storage_controllers(ibmc, storage_controllers)
    if not verify_ret.get(RESULT):
        return verify_ret

    ret = {RESULT: True, MSG: ''}
    result_list = []
    flag = True

    for storage_controller in storage_controllers:
        modify_storage_controller_ret = modify_storage_controller_request(ibmc, storage_controller)
        result_list.append({storage_controller.get(STORAGE_ID): modify_storage_controller_ret})
        if not modify_storage_controller_ret.get(RESULT):
            flag = False

    if flag:
        log_msg = "Modify storage controllers configuration Successfully. The result is: %s" % result_list
        set_result(ibmc.log_info, log_msg, True, ret)
    else:
        log_msg = "Failed to modify storage controllers configuration. The result is: %s" % result_list
        set_result(ibmc.log_error, log_msg, False, ret)

    return ret


def verify_storage_controllers(ibmc, storage_controllers):
    """
    Function:
        verify user set storage controllers
    Args:
        ibmc : Class that contains basic information about iBMC
        storage_controllers : user set storage controllers information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2023/12/07 13:58
    """
    ret = {RESULT: True, MSG: ''}

    if not isinstance(storage_controllers, list):
        log_msg = 'The storage controllers is incorrect, please set it in the modify_storage_controller.yml file'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    if len(storage_controllers) == 0:
        log_msg = 'The storage controllers is null, please set it in the modify_storage_controller.yml file'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    all_raid_storage_id = get_all_storage_id(ibmc)
    for storage_controller in storage_controllers:
        storage_id = storage_controller.get(STORAGE_ID)
        ret = verify_storage_id(ibmc, storage_id, all_raid_storage_id)
        if not ret.get(RESULT):
            return ret

    return ret


def modify_storage_controller_request(ibmc, storage_controller):
    """
    Function:
        Send modify storage controller configuration request
    Args:
        ibmc : Class that contains basic information about iBMC
        storage_controller : User-set storage controller information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2023/12/8 18:55
    """
    storage_id = storage_controller.get(STORAGE_ID)
    url = "%s/Storages/%s/" % (ibmc.system_uri, storage_id)
    token = ibmc.bmc_token
    ret = {RESULT: True, MSG: ''}
    etag, before_storage_controller = ibmc.get_etag_and_message(url)
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}

    oem_info = ibmc.oem_info
    oem_ret = get_modify_storage_controller_oem(ibmc, storage_controller)
    if not oem_ret.get(RESULT):
        return oem_ret

    oem = oem_ret.get(OEM)
    payload = {'StorageControllers': [{OEM: {oem_info: oem}}]}

    try:
        response = ibmc.request('PATCH', resource=url, headers=headers,
                                data=payload, tmout=30)
        extended_info_ret = handle_modify_storage_controller_response(ibmc, response, storage_controller,
                                                                      before_storage_controller)
        extended_info_result = extended_info_ret.get(RESULT)
        extended_info = extended_info_ret.get(MSG)
        if extended_info_result:
            if extended_info:
                set_result(ibmc.log_warn, 'Modify storage controller: %s configuration successfully.'
                                          ' The extended info is %s' % (storage_id, extended_info), True, ret)
            else:
                set_result(ibmc.log_info, 'Modify storage controller: %s configuration successfully.' %
                           storage_id, True, ret)
        else:
            set_result(ibmc.log_error, 'Failed to modify storage controller: %s configuration. The error info is %s' %
                       (storage_id, extended_info), False, ret)

    except Exception as e:
        set_result(ibmc.log_info, 'Failed to modify storage controller: %s configuration. The error info is: %s.' %
                   (storage_id, str(e)), False, ret)

    return ret


def get_all_storage_id(ibmc):
    """
    Function:
        Get all RAID storage information
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        all_storage_id : IDs of all storage resources, Example: [RAIDStorage0,RAIDStorage1]
    Raises:
        Get storage controller resource info failed! or Get storage id failed!
    Date: 2023/12/12 11:02
    """
    token = ibmc.bmc_token
    url = "%s/Storages" % ibmc.system_uri
    headers = {'X-Auth-Token': token}
    payload = {}

    try:
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=30)
        request_code = request_result.status_code
        if request_code != 200:
            msg = "Get storage controller resource info failed! The error code is: %s, " \
                  "The error info is: %s \n" % (str(request_code), str(request_result.json()))
            ibmc.log_error(msg)
            raise Exception(msg)
    except Exception as e:
        msg = "Get storage controller resource info failed! The error info is: %s \n" % str(e)
        ibmc.log_error(msg)
        raise requests.exceptions.RequestException(msg)

    request_result_json = request_result.json()
    all_storage_id = []
    try:
        for members in request_result_json.get("Members"):
            raid_storage_url = members.get("@odata.id")
            all_storage_id.append(str(raid_storage_url).split("/")[-1])
    except Exception as e:
        ibmc.log_error("Get storage id failed! The error info is: %s \n" % str(e))
        raise e
    return all_storage_id


def verify_storage_id(ibmc, storage_id, all_storage_id):
    """
    Function:
        verify reason ability of storage id
    Args:
        ibmc : Class that contains basic information about iBMC
        storage_id: ID of the storage resource
        all_storage_id : IDs of all storage resources

    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2023/12/12 11:07
    """
    ret = {RESULT: True, MSG: ''}
    if not storage_id:
        set_result(ibmc.log_error, "The storage id cannot be empty,"
                                   " please set it in the modify_storage_controller.yml file", False, ret)
        return ret
    if storage_id not in all_storage_id:
        set_result(ibmc.log_error, "The storage id: %s does not exist,"
                                   " please enter the correct storage id in the modify_storage_controller.yml file" %
                   storage_id, False, ret)
        return ret
    return ret


def get_modify_storage_controller_oem(ibmc, storage_controller):
    """
    Function:
        Get oem information for modify storage configuration
    Args:
        ibmc: Class that contains basic information about iBMC
        storage_controller : User-set storage_controller information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2023/12/7 15:04
    """

    oem = {}
    ret = {RESULT: True, MSG: ''}
    if MODE in storage_controller and JBOD_STATE in storage_controller:
        set_result(ibmc.log_error, "Cannot set both mode and JBOD state at the same time,"
                                   " please enter the correct parameter in the modify_storage_controller.yml file.",
                   False, ret)
        return ret

    if JBOD_STATE in storage_controller:
        jbod_state = storage_controller.get(JBOD_STATE)
        if isinstance(jbod_state, bool):
            oem["JBODState"] = jbod_state
        else:
            set_result(ibmc.log_error, "The JBOD state is incorrect, it should be True or False,"
                                       " please enter the correct parameter in the modify_storage_controller.yml file.",
                       False, ret)
            return ret

    if MODE in storage_controller:
        mode = storage_controller.get(MODE)
        if mode in WORK_MODE:
            oem["Mode"] = mode
        else:
            set_result(ibmc.log_error, "The mode is incorrect, it should be RAID or JBOD,"
                                       " please enter the correct parameter in the modify_storage_controller.yml file.",
                       False, ret)
            return ret

    if not oem:
        set_result(ibmc.log_error, "The parameter is empty,"
                                   " please enter the correct parameter in the modify_storage_controller.yml file.",
                   False, ret)
        return ret

    ret[OEM] = oem
    return ret


def compare_storage_property(ibmc, storage, before_storage, property_name):
    """
    Function:
        Compare User-set storage property with the queried storage property
    Args:
        ibmc : Class that contains basic information about iBMC
        storage: User-set storage information
        before_storage: Queried storage information from iBMC
        property_name: Property name
    Returns:
        True or False
    Raises:
        None
    Date: 2023/12/8 15:52
    """
    storage_controllers = before_storage.get("StorageControllers")
    if not storage_controllers:
        return False

    storage_controller = storage_controllers[0]
    oem = storage_controller.get(OEM)
    if not oem:
        return False

    oem_info = oem.get(ibmc.oem_info)
    if not oem_info:
        return False

    if property_name == MODE:
        mode = storage.get(property_name)
        before_mode = oem_info.get("Mode")
        if mode and before_mode and before_mode == mode:
            return True
    elif property_name == JBOD_STATE:
        before_mode = oem_info.get("Mode")
        if before_mode == "JBOD":
            return False
        jbod_state = storage.get(property_name)
        before_jbod_state = oem_info.get("JBODState")
        if isinstance(jbod_state, bool) and isinstance(before_jbod_state, bool) and jbod_state == before_jbod_state:
            return True

    return False


def handle_modify_storage_controller_response(ibmc, response, storage_controller, before_storage_controller):
    """
    Function:
        Handle @Message.ExtendedInfo in response
    Args:
        ibmc : Class that contains basic information about iBMC
        response: Modify storage configuration response from iBMC
        storage_controller: User-set storage controller information
        before_storage_controller: Queried storage controller information from iBMC before modify
    Returns:
        Extended Info
    Raises:
        None
    Date: 2023/12/8 15:52
    """
    status_code = response.status_code
    response_json = response.json()

    ret = {RESULT: True, MSG: []}

    property_mapping = {"Mode": MODE, "JBODState": JBOD_STATE}

    if status_code == 200:
        extend_info_from_bmc = response_json.get("@Message.ExtendedInfo")
    else:
        error = response_json.get("error")
        if not error:
            return ret
        extend_info_from_bmc = error.get("@Message.ExtendedInfo")

    if not extend_info_from_bmc:
        return ret

    for info in extend_info_from_bmc:
        related_properties = info.get("RelatedProperties")
        if not related_properties or len(related_properties) == 0:
            ret[MSG].append(info)

        yml_property = property_mapping.get(related_properties[0].split("/")[-1])
        if yml_property:
            # If the value set by the user is the same as the value before setting, block the error message
            if compare_storage_property(ibmc, storage_controller, before_storage_controller, yml_property):
                continue

            property_msg = {yml_property: {"Message": info.get("Message"), "Resolution": info.get("Resolution")}}
            ret[MSG].append(property_msg)
        else:
            ret[MSG].append(info)

        if info.get("Severity") != "OK":
            ret[RESULT] = False

    return ret
