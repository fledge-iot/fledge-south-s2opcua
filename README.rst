========================================================================
OPC UA Safe & Secure South Plugin
========================================================================

An asynchronous south plugin that registers for data update events on
Objects and Variables in the OPC UA server's Address Space.
The plugin receives data updates when the OPC UA server sends data change notifications to it.

This plugin supports several OPC UA Security Policies and Message Security Modes.
It supports both anonymous access and authentication using username and password.

NOTE:

This plugin assumes the S2OPC OPCUA Toolkit library and its dependencies are available at a specified location in the file system.
See :ref:`Building the S2OPC OPCUA Toolkit and its Dependencies`.

Configuration
-------------

Plugin configuration is described on the `OPC UA Safe & Secure South Plugin <docs/index.rst>`_ documentation page.

Building the S2OPC OPCUA Toolkit and its Dependencies
-----------------------------------------------------

This repository contains the script *fledge-south-s2opcua/requirements.sh* which automates the building of
the S2OPC OPCUA Toolkit and all of its dependencies.
This includes installing all required include files and libraries into the */usr/local* directory tree.
Use of the *requirements.sh* script is highly recommended.

.. code-block:: console

  $ cd ~/dev/fledge-south-s2opcua
  $ ./requirements.sh
  
Note that you must set your default directory to your *fledge-south-s2opcua* directory before running *requirements.sh*.
This script will create the following sub-directories:

- *mbedtls-2.28.7*
- *libexpat*
- *check-0.15.2*
- *S2OPC*

If you need to rebuild any of the S2OPC OPCUA Toolkit's dependendent libraries,
you can extract the appropriate lines of script from *requirements.sh* and execute them manually.
The script *cleanup* is provided to remove all dependent sub-directories if you wish to rebuild all libraries.

Building the OPC UA Safe & Secure South Plugin
----------------------------------------------

To build the OPC UA Safe & Secure South plugin, run the commands:

.. code-block:: console

  $ mkdir build
  $ cd build
  $ cmake ..
  $ make

- By default the Fledge develop package header files and libraries
  are expected to be located in */usr/include/fledge* and */usr/lib/fledge*.
- If **FLEDGE_ROOT** environment variable is set and no -D options are set,
  the header files and libraries paths are pulled from the ones under the
  FLEDGE_ROOT directory.
  Please note that you must first run 'make' in the FLEDGE_ROOT directory.

You may also pass one or more of the following options to 'cmake' to override 
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
