#! /bin/bash
set -e
cd ../..
mkdir xFusion_iBMC_Ansible_Module
cp -r ./Ansible/examples ./xFusion_iBMC_Ansible_Module/examples
cp -r ./Ansible/ibmc_ansible ./xFusion_iBMC_Ansible_Module/ibmc_ansible
cp -r ./Ansible/ssl.cfg ./xFusion_iBMC_Ansible_Module
cp -r ./Ansible/install.py ./xFusion_iBMC_Ansible_Module
cp -r ./Ansible/uninstall.py ./xFusion_iBMC_Ansible_Module
cp ./Ansible/README.md ./xFusion_iBMC_Ansible_Module

chmod 755 -R xFusion_iBMC_Ansible_Module

cd xFusion_iBMC_Ansible_Module
chmod 644 ssl.cfg
chmod 555 *.py

cd ibmc_ansible
chmod 555 *.py

cd ibmc
chmod 555 *.py

cd ../ibmc_redfish_api
chmod 555 *.py

cd ../../examples
chmod 644 *.yml

cd ../..
zip -r "xFusion_iBMC_Ansible_Module_v$1".zip xFusion_iBMC_Ansible_Module

chmod -R 700 xFusion_iBMC_Ansible_Module
rm -rfv xFusion_iBMC_Ansible_Module
echo "Finish"
