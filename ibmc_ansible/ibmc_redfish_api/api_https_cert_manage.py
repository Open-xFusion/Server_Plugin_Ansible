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
from ibmc_ansible.utils import remote_file_path
from ibmc_ansible.ibmc_redfish_api.api_manage_file import upload_file
from ibmc_ansible.ibmc_redfish_api.common_api import wait_task
from ibmc_ansible.ibmc_redfish_api.common_api import result_parse
from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import IBMC_REPORT_PATH

FILE_SERVER = ("sftp", "https", "nfs", "cifs", "scp")
USAGE = {"filetransfer": "FileTransfer"}
CERT_FILE = (".crt", ".cer", ".pem")


def https_cert_import(ibmc, module, file_type):
    """
    Function:
        Importing Certificate Files
    Args:
        ibmc : Class that contains basic information about iBMC
        module : User-configured parameters
        file_type : Type of the file to be imported
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/8/19 21:13
    """
    ret = {'result': True, 'msg': ''}

    uri = None
    info = None
    if file_type == "ca":
        info = "Import remote https server root ca"
        uri = "%s/SecurityService/Actions/SecurityService.ImportRemoteHttpsServerRootCA"\
              % ibmc.manager_uri
    elif file_type == "crl":
        info = "Import remote https server crl"
        uri = "%s/SecurityService/Actions/SecurityService.ImportRemoteHttpsServerCrl" \
              % ibmc.manager_uri

    ibmc.log_info("Start to %s..." % info)

    payload = get_payload(ibmc, module, info, file_type)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Send a post request.
    try:
        request_result = ibmc.request('POST', resource=uri,
                                      headers=headers, data=payload, tmout=60)
    except Exception as e:
        log_error = "%s failed: %s" % (info, str(e))
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    failed_info = "%s failed!" % info
    result = result_parse(ibmc, request_result, failed_info)
    if not result.get('result'):
        return result

    # Importing from the tmp directory does not need to wait.
    if module.params.get("import_location").lower() in ("tmp", "local"):
        log_info = "%s successfully!" % info
        set_result(ibmc.log_info, log_info, True, ret)
        return ret

    request_json = request_result.json()
    log_info = "Send request to %s succeeded, please waitting for task finish." % info
    ibmc.log_info(log_info)
    task_id = request_json.get('Id')

    # The task waiting time does not exceed three and a half minutes.
    task_ret = wait_task(ibmc, task_id, info, wait_time=210)
    if task_ret.get("result") is True:
        log_info = "%s successfully!" % info
        set_result(ibmc.log_info, log_info, True, ret)
    else:
        log_error = "%s failed! The error info is %s" % (info, task_ret.get("msg"))
        set_result(ibmc.log_error, log_error, False, ret)
    return ret


def get_payload(ibmc, module, information, file_type):
    """
    Function:
        Parses user-configured parameters and generates a request body.
    Args:
        ibmc : Class that contains basic information about iBMC
        module : User-configured parameters
        information: Task-related information added to the command output
        file_type: Type of the file to be imported
    Returns:
        payload: request body
    Raises:
         Parameter verification failure information
    Date: 2021/8/19 21:13
    """
    payload = get_cert_path(ibmc, file_type, information, module)

    # can select only one of usage and certID.
    usage = module.params.get("usage")
    cert_id = module.params.get("certID")
    transmission_method = (usage, cert_id)
    if not any(transmission_method):
        log_error = "%s failed! Please use either 'usage' or 'certID'." % information
        ibmc.log_error(log_error)
        raise Exception(log_error)

    if cert_id is not None:
        if cert_id not in (5, 6, 7, 8):
            log_error = "%s failed! The value of certID ranges from 5 to 8." % information
            ibmc.log_error(log_error)
            raise Exception(log_error)
        payload["RootCertId"] = cert_id

    if usage is not None:
        if USAGE.get(usage.lower()) is None:
            log_error = "%s failed! Available value of usage is FileTransfer." % information
            ibmc.log_error(log_error)
            raise Exception(log_error)
        payload["Usage"] = USAGE.get(usage.lower())

    return payload


def get_cert_path(ibmc, file_type, information, module):
    """
    Function:
        Parses user-configured parameters and obtain  a cert_path.
    Args:
        ibmc : Class that contains basic information about iBMC
        module : User-configured parameters
        information: Task-related information added to the command output
        file_type: Type of the file to be imported
    Returns:
        payload: request body
    Raises:
         Parameter verification failure information
    Date: 2021/8/19 21:13
    """
    payload = {"Type": "URI"}
    file_path = module.params.get("certpath")
    if file_path is None:
        log_error = "%s failed! Please set the certpath." % information
        ibmc.log_error(log_error)
        raise Exception(log_error)

    file_name = os.path.basename(file_path)
    extension = os.path.splitext(file_name)[-1]

    # Verifying the Certificate Suffix
    if extension not in CERT_FILE and file_type == "ca":
        log_error = "%s failed! The certpath extension must be in %s." \
                    % (information, CERT_FILE)
        ibmc.log_error(log_error)
        raise Exception(log_error)
    elif extension != ".crl" and file_type == "crl":
        log_error = "%s failed! The certpath extension must be '.crl'." % information
        ibmc.log_error(log_error)
        raise Exception(log_error)

    # Change Content based on the path where the certificate is stored.
    if module.params.get("import_location") is None:
        log_error = "%s failed! Please set the import_location." % information
        ibmc.log_error(log_error)
        raise Exception(log_error)

    location = module.params.get("import_location").lower()
    if location in FILE_SERVER:
        payload["Content"] = remote_file_path(module.params.get("certpath"),
                                              module)
    elif location == "tmp":
        payload["Content"] = file_path

    elif location == "local":
        # Upload the certificate to the tmp directory of the BMC.
        upload_file_res = upload_file(ibmc, file_path)
        if not upload_file_res.get("result"):
            log_error = "%s failed! The detailed " \
                        "information is as follows: %s " \
                        % (information, upload_file_res.get("msg"))
            ibmc.log_error(log_error)
            raise Exception(log_error)
        payload["Content"] = "/tmp/web/%s" % file_name

    else:
        log_error = "%s failed! The import_location parameter is incorrect. " \
                    "Please chose from [tmp, local sftp,https,nfs,cifs,scp]" % information
        ibmc.log_error(log_error)
        raise Exception(log_error)
    return payload


def delete_https_ca(ibmc, module):
    """
    Function:
        Delete https ca
    Args:
        ibmc : Class that contains basic information about iBMC
        module : User-configured parameters
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/8/27 21:13
    """
    ibmc.log_info("Start to delete the certificate...")
    ret = {'result': True, 'msg': ''}
    failed_info = "Delete remote https server root ca failed!"

    # Available values for cert_id: [5, 6, 7, 8].
    cert_id = module.params.get("certID")
    if cert_id not in (5, 6, 7, 8):
        log_error = "%s The value of certID ranges from 5 to 8." % failed_info
        ibmc.log_error(log_error)
        raise Exception(log_error)

    payload = {"RootCertId": cert_id}
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    uri = "%s/SecurityService/Actions/SecurityService.DeleteRemoteHttpsServerRootCA"\
          % ibmc.manager_uri

    # Send a post request.
    try:
        request_result = ibmc.request('POST', resource=uri,
                                      headers=headers, data=payload, tmout=60)
    except Exception as e:
        log_error = "%s The error info is %s" % (failed_info, str(e))
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    result = result_parse(ibmc, request_result, failed_info)
    if not result.get('result'):
        return result

    log_info = "Delete remote https server root ca successful!"
    set_result(ibmc.log_info, log_info, True, ret)
    return ret


def set_https_cert_verification(ibmc, module):
    """
    Function:
        Set https cert verification
    Args:
        ibmc : Class that contains basic information about iBMC
        module : User-configured parameters
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/8/27 21:13
    """
    ibmc.log_info("Start to set https cert verification...")
    ret = {'result': True, 'msg': ''}
    failed_info = "Set https cert verification failed!"

    verify = module.params.get("verify_cmd")
    if verify is True:
        cmd = True
    elif verify is False:
        cmd = False
    else:
        log_error = "%s Please set verify_cmd with True or False" % failed_info
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    payload = {"HttpsTransferCertVerification": cmd}
    uri = "%s/SecurityService" % ibmc.manager_uri
    token = ibmc.get_token()
    etag = ibmc.get_etag(uri)
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token,
               'If-Match': etag}

    # Send a Patch request.
    try:
        request_result = ibmc.request('PATCH', resource=uri,
                                      headers=headers, data=payload, tmout=60)
    except Exception as e:
        log_error = "%s The error info is %s" % (failed_info, str(e))
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    result = result_parse(ibmc, request_result, failed_info)
    if not result.get('result'):
        return result

    log_info = "Set https cert verification successful!"
    set_result(ibmc.log_info, log_info, True, ret)
    return ret


def get_security_service_information(ibmc):
    """
    Function:
        Get security service information and save as a file
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/8/27 21:13
    """
    ibmc.log_info("Start to get security service information...")
    ret = {'result': True, 'msg': ''}
    failed_info = "Get security service information failed!"

    uri = "%s/SecurityService" % ibmc.manager_uri
    token = ibmc.get_token()
    # Initialize headers
    headers = {'X-Auth-Token': token}

    # Send a get request.
    try:
        request_result = ibmc.request('GET', resource=uri,
                                      headers=headers, tmout=60)
    except Exception as e:
        log_error = "%s The error info is %s" % (failed_info, str(e))
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    result = result_parse(ibmc, request_result, failed_info)
    if not result.get('result'):
        return result

    request_json = request_result.json()
    name = "%s_SecurityServiceInfo.json" % str(ibmc.ip)
    file_name = os.path.join(IBMC_REPORT_PATH, "security_service", name)
    write_result(ibmc, file_name, request_json)

    log_info = "Get security service information successful! " \
               "For more detail information please refer to %s" % file_name
    set_result(ibmc.log_info, log_info, True, ret)
    return ret
