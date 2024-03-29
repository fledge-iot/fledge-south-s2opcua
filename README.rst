========================================================================
OPC UA S2OPC South plugin 
========================================================================

A simple asynchronous OPC UA plugin that registers for change events on
OPC UA objects.
This plugin supports several OPC UA Security Policies and Message Security Modes.
It supports both anonymous access and authentication using username and password.

NOTE:

This plugin assumes the S2OPC OPCUA library is available at a specified location
in the file system, see below.

Configuration
-------------

This configuration of this plugin requires following parameters to be set:

Asset Name
  An asset name prefix that is added to the OPC UA variables retrieved from the OPC UA server

OPCUA Server URL
  The URL used to connect the server, of the form *opc.tcp://<hostname>:<port>/...*

OPCUA Object Subscriptions
  An array of OPC UA node names that will control the subscription to
  variables in the OPC UA server.

  If the subscribeById option is set then this is an array of node
  Id's. Each node Id should be of the form ns=..;s=... Where ns is a
  namespace index and s is the node id string identifier.

  Presently only subscription based on node ID is supported.
  
  Configuration examples:

.. code-block:: console

    { "subscriptions" : [  "ns=3;i=1001", "ns=3;i=1002" ] }

It's also possible to specify an empty subscription array:

.. code-block:: console

    {"subscriptions":[]}

Note: depending on OPC UA server configuration (number of objects, number of variables)
this empty configuration might take a while to be loaded.

Object names, variable names and NamespaceIndexes can be easily retrieved
browsing the given OPC UA server using OPC UA clients, such as UaExpert

https://www.unified-automation.com/downloads/opc-ua-clients.html

Most examples come from the Simulation Object in the Prosys OPC UA Simulation Server:

https://www.prosysopc.com/products/opc-ua-simulation-server/

Min Reporting Interval
  The minimum reporting interval for data change notifications

Security Mode
  Security mode to use while connecting to OPCUA server. Options are "None", "Sign" & "SignAndEncrypt."

Security Policy
  Security policy to use while connecting to OPCUA server. Options are "None", "Basic256" & "Basic256Sha256."

User Authentication Policy
  User authentication policy to use while connecting to OPCUA server. Supported values are "anonymous" & "username."

Username
  Username to use when userAuthPolicy is set to "username."

Password
  Password to use when userAuthPolicy is set to "username."

CA Certificate Authority
  CA Certificate Authority file path in DER format. Applicable when securityMode is "Sign" or "SignAndEncrypt."

Server Public Certificate
  Server certificate file path in DER format. Applicable when securityMode is "Sign" or "SignAndEncrypt."

Client Public Certificate
  Client certificate file path in DER format. Applicable when securityMode is "Sign" or "SignAndEncrypt."

Client Private Key
  Client private key file path in PEM format. Applicable when securityMode is "Sign" or "SignAndEncrypt."

Certificate Revocation List
  Certificate Revocation List in DER format. Applicable when securityMode is "Sign" or "SignAndEncrypt."

Debug Trace File
  Enable the S2OPCUA OPCUA Toolkit trace file for debugging. If enabled, log files will appear in the directory */usr/local/fledge/data/logs*.

Building S2OPC
------------------

To build S2OPC and its dependencies:

* libmbedtls-dev:
.. code-block:: console

  $ sudo apt-get install -y libmbedtls-dev

* libexpat:
.. code-block:: console

  $ cd ~/dev
  $ git clone https://github.com/libexpat/libexpat.git
  $ cd libexpat/expat
  $ rm -f CMakeCache.txt ; mkdir -p build ; cd build; cmake -D CMAKE_INSTALL_PREFIX=/usr/local -D EXPAT_BUILD_PKGCONFIG=ON -D EXPAT_ENABLE_INSTALL=ON -D EXPAT_SHARED_LIBS=ON .. && make -j4 && sudo make install; cd -

* libcheck:
.. code-block:: console

  $ cd ~/dev
  $ wget https://github.com/libcheck/check/releases/download/0.15.2/check-0.15.2.tar.gz
  $ tar xf check-0.15.2.tar.gz
  $ cd check-0.15.2
  $ Make these changes in CMakeLists.txt
        251c251,253
        <     add_link_options("-pthread")
        ---
        >     set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pthread")
        >     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
        >     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

  $ rm -f CMakeCache.txt ; mkdir -p build ; cd build; cmake .. && make -j4 && sudo make install; cd -

* S2OPC:
.. code-block:: console

  $ cd ~/dev
  $ git clone https://gitlab.com/systerel/S2OPC.git --branch S2OPC_Toolkit_1.4.1 --depth 1
  $ git clone https://github.com/fledge-iot/fledge-south-s2opcua.git
  $ cd S2OPC
  $ cp ../fledge-south-s2opcua/S2OPC.patch .
  $ git apply S2OPC.patch
  $ cp ./src/Common/opcua_types/sopc_encodeabletype.h ../fledge-south-s2opcua/include
  $ Make this change in ../fledge-south-s2opcua/include/sopc_encodeabletype.h:
      * Locate the string: *typedef const struct SOPC_EncodeableType*
      * Change it to: *typedef struct SOPC_EncodeableType* (that is, remove the *const*)
  $ BUILD_SHARED_LIBS=OFF; CMAKE_INSTALL_PREFIX=/usr/local; ./build.sh; echo; echo "BUILD done, INSTALLING..."; echo; cd build; sudo make install; cd -

Alternatively run the script *fledge-south-s2opcua/requirements.sh* to automate these steps.
This includes placing a copy of the S2OPC shared library and its dependencies in */usr/local/lib*.

.. code-block:: console

  $ cd ~/dev/fledge-south-s2opcua
  $ ./requirements.sh
  
Note that you should set your default directory to your *fledge-south-s2opcua* directory before running *requirements.sh*.
This script will create *libexpat*, *check-0.15.2* and *S2OPC* as sub-directories of *fledge-south-s2opcua*.
This is different from the manual procedure above but will still result in the *S2OPC* libraries being placed in */usr/local/lib*.

Build
-----

To build the OPC UA S2OPC South plugin run the commands:

.. code-block:: console

  $ mkdir build
  $ cd build
  $ cmake ..
  $ make

- By default the Fledge develop package header files and libraries
  are expected to be located in /usr/include/fledge and /usr/lib/fledge
- If **FLEDGE_ROOT** env var is set and no -D options are set,
  the header files and libraries paths are pulled from the ones under the
  FLEDGE_ROOT directory.
  Please note that you must first run 'make' in the FLEDGE_ROOT directory.

You may also pass one or more of the following options to cmake to override 
this default behaviour:

- **FLEDGE_SRC** sets the path of a Fledge source tree
- **FLEDGE_INCLUDE** sets the path to Fledge header files
- **FLEDGE_LIB sets** the path to Fledge libraries
- **FLEDGE_INSTALL** sets the installation path of Random plugin

NOTE:
 - The **FLEDGE_INCLUDE** option should point to a location where all the Fledge 
   header files have been installed in a single directory.
 - The **FLEDGE_LIB** option should point to a location where all the Fledge
   libraries have been installed in a single directory.
 - 'make install' target is defined only when **FLEDGE_INSTALL** is set

Examples:

- no options

  $ cmake ..

- no options and FLEDGE_ROOT set

  $ export FLEDGE_ROOT=/some_fledge_setup

  $ cmake ..

- set FLEDGE_SRC

  $ cmake -DFLEDGE_SRC=/home/source/develop/Fledge  ..

- set FLEDGE_INCLUDE

  $ cmake -DFLEDGE_INCLUDE=/dev-package/include ..
- set FLEDGE_LIB

  $ cmake -DFLEDGE_LIB=/home/dev/package/lib ..
- set FLEDGE_INSTALL

  $ cmake -DFLEDGE_INSTALL=/home/source/develop/Fledge ..

  $ cmake -DFLEDGE_INSTALL=/usr/local/fledge ..
