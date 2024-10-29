#!/usr/bin/env bash

##---------------------------------------------------------------------------
## Copyright (c) 2022 Dianomic Systems Inc.
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##---------------------------------------------------------------------------

##
## Author: Amandeep Singh Arora, Mark Riddoch
##
os_name=`(grep -o '^NAME=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')`
os_version=`(grep -o '^VERSION_ID=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')`
echo "Platform is ${os_name}, Version: ${os_version}"

# mbedtls-dev:
if [[  $os_name == *"Red Hat"* || $os_name == *"CentOS"* ]]; then
	echo RHEL/CentOS not currently supported by this plugin
	exit 1
else
	(
		wget https://github.com/Mbed-TLS/mbedtls/archive/v2.28.7.tar.gz
		tar xzvf v2.28.7.tar.gz
		cd mbedtls-2.28.7
		mkdir build
		cd build
		cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DUSE_SHARED_MBEDTLS_LIBRARY=OFF ..
		make
		sudo make install
	)
fi

# libexpat:
libexpat_version="2.6.0"
libexpat_branch="R_${libexpat_version//./_}"
git clone https://github.com/libexpat/libexpat.git --branch ${libexpat_branch} --depth 1
(
	cd libexpat/expat
	./buildconf.sh && \
	./configure && \
	make && \
	sudo make install
)


# libcheck:
wget https://github.com/libcheck/check/releases/download/0.15.2/check-0.15.2.tar.gz
tar xf check-0.15.2.tar.gz
(
	cd check-0.15.2
	cp ../check-0.15.2_CMakeLists.txt.patch .
	patch < check-0.15.2_CMakeLists.txt.patch  # update the CMakeLists.txt file
	rm -f CMakeCache.txt
	mkdir -p build
	cd build
	cmake .. && make -j4 && sudo make install
)

# S2OPC
git clone https://gitlab.com/systerel/S2OPC.git --branch S2OPC_Toolkit_1.5.0 --depth 1
(
	cd S2OPC
	BUILD_SHARED_LIBS=1 CMAKE_INSTALL_PREFIX=/usr/local ./build.sh
	echo
	echo "BUILD done, INSTALLING..."
	echo
	cd build
	sudo make install
	sudo cp ../src/ClientServer/frontend/client_wrapper/libs2opc_client_config_custom.h /usr/local/include/s2opc/clientserver
)
