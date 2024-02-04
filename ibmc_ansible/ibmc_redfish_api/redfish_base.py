#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import json
import ssl
import re
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager as PoolManager
from requests.packages.urllib3.connection import HTTPSConnection as HTTPSConnection
from ibmc_ansible.ibmc_logger import log

try:
    from ssl import PROTOCOL_TLSv1_2

    IMPORT_TLS = True
except ImportError as e:
    IMPORT_TLS = False
    log.error(str(e))

try:
    from ssl import PROTOCOL_SSLv23 as PROTOCOL_TLS
except ImportError as e:
    from ssl import PROTOCOL_TLS as PROTOCOL_TLS

    log.error(str(e))

from ibmc_ansible.utils import read_ssl_ciphers
from ibmc_ansible.utils import read_ssl_verify
from ibmc_ansible.utils import read_ssl_force_tls

LOCATION = "Location"
MESSAGE = "message"
STATUS_CODE = "status_code"
HEADERS = "headers"
ETAG_UPPER = "ETag"
ETAG_LOWER = "etag"


class IbmcBaseConnect():
    """
    Args:
        None
    Returns:
        None
    Raises:
        None
    Date: 10/19/2019
    """

    def __init__(self, param_dic, input_log=None, report=None, debug=None):
        self.bmc_token = ''
        self.oem_info = ''
        self.bmc_session_id = ''
        self.user = param_dic['ibmc_user']
        self.pswd = param_dic['ibmc_pswd']
        self.ip = param_dic['ibmc_ip']
        self.log = input_log
        self.verify = read_ssl_verify(input_log)
        self.tls1_2 = read_ssl_force_tls(input_log)
        self.report = report
        self.session = requests.session()
        self.ciphers = read_ssl_ciphers(input_log)
        if (self.ciphers is not None) and (self.ciphers != ''):
            ssl._DEFAULT_CIPHERS = self.ciphers
        else:
            ssl._DEFAULT_CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                                    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
                                    "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:"
                                    "DHE-DSS-AES128-GCM-SHA256:DHE-DSS-AES256-GCM-SHA384:"
                                    "ECDHE-RSA-CHACHA20-POLY1305")

        class ComAdapter(HTTPAdapter):

            def init_poolmanager(self, *pool_args, **pool_kwargs):
                if "ssl_context" in dir(HTTPSConnection(host="")):
                    context = ssl.SSLContext(PROTOCOL_TLS)
                    context.set_ciphers(ssl._DEFAULT_CIPHERS)
                    self.poolmanager = PoolManager(
                        *pool_args, ssl_context=context, **pool_kwargs)
                else:
                    self.poolmanager = PoolManager(
                        *pool_args, **pool_kwargs)

        self.adapter = ComAdapter()
        if IMPORT_TLS:
            class TLS12Adapter(HTTPAdapter):
                """
                Fuction : force to user tls1.2
                Args:
                    None
                Returns:
                    None
                Raises:
                    None
                Date: 10/19/2019
                """

                def init_poolmanager(self, *pool_args, **pool_kwargs):
                    if "ssl_context" in dir(HTTPSConnection(host="")):
                        context = ssl.SSLContext(PROTOCOL_TLSv1_2)
                        context.set_ciphers(ssl._DEFAULT_CIPHERS)
                        self.poolmanager = PoolManager(
                            *pool_args, ssl_version=PROTOCOL_TLSv1_2, ssl_context=context, **pool_kwargs)
                    else:
                        self.poolmanager = PoolManager(
                            *pool_args, ssl_version=PROTOCOL_TLSv1_2, **pool_kwargs)

            if self.tls1_2:
                self.adapter = TLS12Adapter()
        else:
            if self.tls1_2:
                raise Exception("import ssl.PROTOCOL_TLSv1_2 exception")
        self.session.mount("https://", self.adapter)
        self.debug = debug
        self.create_session()
        self.root_uri = ''.join(["https://%s" % self.ip, "/redfish/v1"])
        system_number = self._get_system_uri()
        number = system_number.split("/")[4]
        self.chassis_uri = "%s/Chassis/%s" % (self.root_uri, number)
        self.manager_uri = "%s/Managers/%s" % (self.root_uri, number)
        self.eventsvc_uri = "%s/EventService" % self.root_uri
        self.system_uri = "%s/Systems/%s" % (self.root_uri, number)

    def __enter__(self):
        """
        Args:
            self
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        return self

    def __exit__(self, *args):
        """
        Args:
            *args
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        self._close()

    def debug_info(self, msg):
        """
        Args:
            msg
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        if self.debug is None:
            return
        else:
            self.debug(msg)

    def log_info(self, msg):
        """
        Args:
            msg
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        if self.log is None:
            return
        else:
            self.log.info("%s -- %s" % (self.ip, msg))

    def log_warn(self, msg):
        """
        Args:
            msg
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        if self.log is None:
            return
        else:
            self.log.warn("%s -- %s" % (self.ip, msg))

    def report_info(self, msg):
        """
        Args:
            msg
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        if self.report is None:
            return
        else:
            self.report.info("%s -- %s" % (self.ip, msg))

    def log_error(self, msg):
        """
        Args:
            msg
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        if self.log is None:
            return
        else:
            self.log.error("%s -- %s" % (self.ip, msg))

    def report_error(self, msg):
        """
        Args:
            msg
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        if self.report is None:
            return
        else:
            self.report.error("%s -- %s" % (self.ip, msg))

    def request(self, method, resource, headers=None, data=None, tmout=10):
        """
        Args:
                method            (str):
                resource            (str):
                headers            (dict):
                data            (dict):
                tmout            (int):

        Returns:
            response
        Raises:
            Exception
        Date: 10/19/2019
        """
        if headers is None:
            headers = {
                'X-Auth-Token': self.bmc_token,
                'content-type': 'application/json'
            }

        if isinstance(data, dict):
            payload = json.dumps(data)
        else:
            payload = data
        url = resource
        try:
            if method == 'POST':
                r = self.session.post(
                    url, data=payload, headers=headers, verify=self.verify, timeout=tmout)
            elif method == 'GET':
                r = self.session.get(
                    url, data=payload, headers=headers, verify=self.verify, timeout=tmout)
            elif method == 'DELETE':
                r = self.session.delete(
                    url, data=None, headers=headers, verify=self.verify, timeout=tmout)
            elif method == 'PATCH':
                r = self.session.patch(
                    url, data=payload, headers=headers, verify=self.verify, timeout=tmout)
            else:
                raise Exception("Request method not support")
        except Exception as ex:
            self.log_error("request exception ,exception is :%s" % str(ex))
            raise
        return r

    def create_session(self, timeout=10):
        """
        Args:
                timeout            (int): overtime time
        Returns:
            bool
        Raises:
            None
        Date: 10/19/2019
        """
        url = 'https://%s/redfish/v1/SessionService/Sessions' % self.ip
        payload = {'UserName': self.user, 'Password': self.pswd}
        try:
            r = self.request('POST', url, data=payload, tmout=timeout)
        except Exception as ex:
            self.log_error(
                "Create session exception, The error info is: %s" % str(ex))
            raise
        try:
            if r is None:
                self.log_error(
                    "Failed to create session, The response is none")
                raise Exception(
                    "Failed to create session, The response is none")
            elif r.status_code == 201:
                index = r.headers[LOCATION].find("/redfish")
                if index != -1:
                    location = r.headers[LOCATION][index:]
                    session_id = location.split('/')[5]
                else:
                    location = r.headers[LOCATION]
                    session_id = location.split('/')[5]
                token = r.headers['X-Auth-Token']
                self._set_token(token)
                self._set_bmc_session_id(session_id)
                oem = r.json().get("Oem")
                (self.oem_info, oem_detail), = oem.items()

            else:
                error_msg = r.json()
                log_error = "Failed to create session, The error code is: %s. " \
                            "The error info is %s" % (r.status_code, str(error_msg))
                self.log_error(log_error)
                raise Exception(log_error)
        except Exception as ex:
            self.log_error(
                "Create session exception, The error info is: %s" % str(ex))
            raise

    def delete_session(self, timeout=10):
        """
        Args:
                timeout            (int):   overtime time
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        session_id = self._get_bmc_session_id()
        url = 'https://%s/redfish/v1/SessionService/Sessions/%s' % (
            self.ip, session_id)
        playload = {'UserName': self.user, 'Password': self.pswd}
        try:
            r = self.request('DELETE', url, data=playload, tmout=timeout)
        except Exception as ex:
            self.log_error("Failed to delete session, The error info is: %s" % str(ex))
            raise
        if r is None:
            ret = {
                STATUS_CODE: 999,
                MESSAGE: 'HTTP request exception!!',
                HEADERS: ''
            }
        elif r.status_code == 200:
            ret = {
                STATUS_CODE: r.status_code,
                MESSAGE: r.content,
                HEADERS: r.headers
            }
        elif r.status_code == 401:
            self.log_warn("delete session failed. The error code is: 401 ")
            ret = {
                STATUS_CODE: r.status_code,
                MESSAGE: r.content,
                HEADERS: r.headers
            }
        else:
            raise Exception("Failed to delete session, The error code is: %s, The error info is %s" %
                            (str(r.status_code), str(r.json())))
        return ret

    def get_server_url(self, ret):
        """
        Args:
            ret
        Returns:
            uri
        Raises:
            Exception
        Date: 10/27/2020
        """
        members_list = ret['Members']
        if not members_list:
            raise Exception("Members is null")
        uri = None
        try:
            for member in members_list:
                member_uri = member.get('@odata.id')
                number = member_uri.split("/")[-1]
                if "hmm" in number.lower():
                    uri = "%s/Managers/%s" % (self.root_uri, number)
                    response = self.request('GET', uri)
                    ret = response.json()
                    state = ret.get('Status').get('State')
                    if state == "Enabled":
                        return member_uri
            return ret['Members'][0]['@odata.id']
        except Exception as ex:
            self.log_error("Get managers_uri failed! The uri is : %s, The error is %s" % (
                str(uri), str(ex)))
            raise

    def get_etag(self, uri):
        """
        Args:
                uri            (str):    url of etag
        Returns:
            etag
        Raises:
            Exception
        Date: 10/19/2019
        """
        etag, _ = self.get_etag_and_message(uri)
        return etag

    def get_etag_and_message(self, uri):
        """
        Args:
                uri            (str):    url of etag
        Returns:
            etag, message
        Raises:
            Exception
        Date: 12/8/2023
        """
        etag = ''
        # get Etag
        try:
            response = self.request('GET', uri, tmout=100)
        except Exception as ex:
            self.log_error(
                "Failed to get etag, The error info is: %s" % str(ex))
            raise
        if response is None:
            raise Exception("get etag response is none")
        elif response.status_code == 200:
            ret = {STATUS_CODE: 200, MESSAGE: response.json(), HEADERS: response.headers}
            if ret.get(HEADERS):
                if ETAG_UPPER in ret.get(HEADERS).keys():
                    etag = ret[HEADERS][ETAG_UPPER]
                elif ETAG_LOWER in ret.get(HEADERS).keys():
                    etag = ret[HEADERS][ETAG_LOWER]
        else:
            try:
                ret = {
                    STATUS_CODE: response.status_code,
                    MESSAGE: response.json(), HEADERS: response.headers
                }
            except Exception as ex:
                self.log_error(
                    "Failed to get etag, The error info is: %s" % str(ex))
                raise
            if ETAG_UPPER in ret[HEADERS].keys():
                etag = ret[HEADERS][ETAG_UPPER]
            if ETAG_LOWER in ret[HEADERS].keys():
                etag = ret[HEADERS][ETAG_LOWER]
        return etag, ret[MESSAGE]

    def get_task_info(self, taskid):
        """
        Args:
                taskid            (str):   task id
        Returns:
            task info response json
        Raises:
            Exception
        Date: 10/19/2019
        """
        token = self.get_token()
        headers = {'content-type': 'application/json', 'X-Auth-Token': token}
        uri = "%s/TaskService/Tasks/%s" % (self.root_uri, taskid)
        payload = {}
        try:
            r = self.request('GET', resource=uri,
                             headers=headers, data=payload, tmout=300)
        except Exception as ex:
            self.log_error(
                "Failed to get task, The error info is: %s" % (str(ex)))
            raise
        return r

    def get_token(self):
        """
        Args:
            self
        Returns:
            self.bmc_token
        Raises:
            None
        Date: 10/19/2019
        """
        return self.bmc_token

    def get_systems_resource(self):
        """
        Function:
            get systems resource
        Args:
                self
        Returns:
            json
        Raises:
            None
        Date: 10/30/2019
        """
        token = self.get_token()
        headers = {'content-type': 'application/json', 'X-Auth-Token': token}
        payload = {}
        try:
            systems_r = self.request(
                'GET', resource=self.system_uri, headers=headers, data=payload, tmout=30)
            if systems_r.status_code != 200:
                raise Exception(
                    "Get systems info send command exception, error code:%d" % systems_r.status_code)
            else:
                systems_json = systems_r.json()
        except Exception as ex:
            self.log_error(
                "Get systems info send command exception, %s" % str(ex))
            raise ex
        return systems_json

    def get_chassis_resource(self):
        """
        Function:
            get chassis resource
        Args:
                self
        Returns:
            None
        Raises:
            None
        Date: 10/30/2019
        """
        # get chassis resource
        token = self.get_token()
        headers = {'content-type': 'application/json', 'X-Auth-Token': token}
        payload = {}
        try:
            chassis_r = self.request(
                'GET', resource=self.chassis_uri, headers=headers, data=payload, tmout=30)
            if chassis_r.status_code != 200:
                raise Exception(
                    "Get chassis info send command exception, error code:%d" % chassis_r.status_code)
            else:
                chassis_json = chassis_r.json()

        except Exception as ex:
            self.log_error(
                "Get chassis info send command exception, %s" % str(ex))
            raise ex
        return chassis_json

    def get_manager_resource(self):
        """
        Function:
            get manager resource
        Args:
                self
        Returns:
            None
        Raises:
            None
        Date: 10/30/2019
        """

        # get manager resource
        token = self.get_token()
        headers = {'content-type': 'application/json', 'X-Auth-Token': token}
        payload = {}
        try:
            manager_r = self.request(
                'GET', resource=self.manager_uri, headers=headers, data=payload, tmout=30)
            if manager_r.status_code != 200:
                raise Exception(
                    "Get manager info send command exception, error code:%d" % manager_r.status_code)
            else:
                manager_json = manager_r.json()

        except Exception as ex:
            self.log_error(
                "Get manager info send command exception, %s" % str(ex))
            raise ex
        return manager_json

    def get_ibmc_version(self):
        """
        Function:
           check bmc version
        Args:
            self
        Returns:
           version
        Raises:
           Exception
        Date: 10/30/2019
        """
        try:
            version = self.get_manager_resource()[u'FirmwareVersion']
        except Exception as ex:
            self.log_error("get iBMC version exception! Exception:%s" % str(ex))
            raise
        return version

    def get_sp_version(self):
        """
        Function:
           get sp version
        Args:
            self
        Returns:
           version
        Raises:
           Exception
        Date: 10/30/2019
        """
        token = self.get_token()
        headers = {'content-type': 'application/json', 'X-Auth-Token': token}
        payload = {}
        uri = "%s/SPService" % self.manager_uri
        r = self.request('GET', resource=uri, headers=headers,
                         data=payload, tmout=10)
        if r.status_code == 200:
            if r.json().get("Version") is None:
                raise Exception(
                    " r.json() do not has key version r.json():%s" % str(r.json()))
            return r.json().get("Version")
        else:
            self.log_error(
                "get_sp_version failed ,error code is :%s" % str(r.status_code))
            raise Exception(
                "get_sp_version failed ,error code is :%s" % str(r.status_code))

    def check_ibmc_version(self, except_version):
        """
        Function:
            check bmc version is valid
        Args:
            except_version (str):
        Returns:
           bool
        Raises:
           Exception
        Date: 10/30/2019
        """
        old_vesion_style = r'^\d+.\d*\d$'
        new_version_style = r'^\d+.\d+.\d+.\d*\d$'

        bmc_version = self.get_ibmc_version()
        self.log_info("bmc_version is " + bmc_version)
        # bmc version is old style and  except veison is new style
        if re.match(old_vesion_style, bmc_version) and re.match(new_version_style, except_version):
            self.log_info(
                "bmc_version and except_version is not the same style")
            return True
        # bmc version is new style and  except veison is old style
        if re.match(new_version_style, bmc_version) and (re.match(old_vesion_style, except_version)):
            self.log_info(
                "bmc_version and  except_version is not the same style")
            return True
        if bmc_version is None:
            raise Exception("get bmc version return none")
        if bmc_version >= except_version:
            return True
        return False

    def check_sp_version(self, except_version):
        """
        Function:
            check bmc version is valid
        Args:
            except_version   (str):
        Returns:
           bool
        Raises:
           Exception
        Date: 10/30/2019
        """
        sp_version = self.get_sp_version()
        if sp_version is None:
            raise Exception("get sp version return none")
        if sp_version.get("APPVersion") is None:
            raise Exception("get APPVersion return none")
        if sp_version.get("APPVersion") >= except_version:
            return True
        return False

    def _get_system_uri(self):
        """
        Args:
            self
        Returns:
            uri
        Raises:
            None
        Date: 10/19/2019
        """
        uri = "%s/Managers" % self.root_uri
        try:
            response = self.request('GET', uri)
        except Exception as ex:
            self.log_error(
                "Get system_uri failed! The uri is : %s, The error is %s" % (str(uri), str(ex)))
            raise
        if response is None:
            self.log_error("get system_uri failed! uri :%s " % uri)
            raise Exception("get system uri exception response is none")
        else:
            if response.status_code != 200:
                self.log_error("get system_uri failed, The response is: %s, The uri is: %s" % (
                    str(response), str(uri)))
                raise Exception(
                    "get system_uri failed, The response is: %s" % str(response))
            try:
                ret = response.json()
                ret = self.get_server_url(ret)
            except Exception as ex:
                self.log_error(
                    "Failed to get system_uri, The error info is: %s" % str(ex))
                raise
        return ret

    def _get_bmc_session_id(self):
        """
        Args:
            self
        Returns:
            self.bmc_session_id
        Raises:
            None
        Date: 10/19/2019
        """
        return self.bmc_session_id

    def _set_token(self, token):
        """
        Args:
            token
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        self.bmc_token = token

    def _set_bmc_session_id(self, session_id):
        """
        Args:
                session_id            (str):   session_id
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        self.bmc_session_id = session_id

    def _close(self):
        """
        Args:
            self
        Returns:
            None
        Raises:
            None
        Date: 10/19/2019
        """
        try:
            self.delete_session()
        except Exception as ex:
            self.log_error(str(ex))
        try:
            self.session.close()
        except Exception as ex:
            self.log_error(str(ex))


if __name__ == '__main__':
    pass
