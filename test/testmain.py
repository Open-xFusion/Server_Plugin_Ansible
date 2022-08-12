#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019 xFusion Digital Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail
import sys

def testdebug(str):
    print str
sys.path.append("../")

from ibmc_ansible.ibmc_redfish_api.redfish_base import *
from ibmc_ansible.ibmc_redfish_api.api_manage_account import *
from ibmc_ansible.utils import *
from ibmc_ansible.ibmc_redfish_api.api_power_manager import *
LOG_FILE = "d:/ansibleibmc.log"
REPORT_FILE = "d:/ansibleibmc.report"
log,report=ansible_get_loger(LOG_FILE,REPORT_FILE,"ansibleibmc")

def main():


   r=requests.get(url="https://xfusion.xfusion/redfish/v1/Managers/1",verify=True,auth=("root","xFusion@123") )
   print (r.json())
"""
    params = { 
               "ibmc_ip":"172.26.100.7" ,
               "ibmc_user":"root",
               "ibmc_pswd":"xFusion@123" 
            }


    with  IbmcBaseConnect(params,log,report,debug=testdebug) as bmctest:

            # ret=getAccounts(bmctest)        
            #ret="test"
            #ret=getAccounts(bmctest)
            #bmctest.debug(ret)
            #ret=getAccountsId(bmctest,"root")
            #bmctest.debug(ret)

            print bmctest.read_ssl_cfg()
            #ret=get_accounts(bmctest)
            #ret=create_account(bmctest,"testAccount","xFusion@123","Administrator")
            #ret=get_accounts(bmctest)

            #bmctest.debug(ret)
            #ret=delete_account(bmctest,"testAccount")
            #bmctest.debug(ret)
            #ret=get_accounts(bmctest)
            #bmctest.debug(ret)
           

            #ret=get_power_status(bmctest)
            #bmctest.debug(ret)
            
            #ret=manage_power(bmctest,"poweroff")
            
            #ibmctest.debug(ret)
            #ret=get_power_status(bmctest)
            #bmctest.debug(ret)
"""





if __name__ == '__main__':
    main()