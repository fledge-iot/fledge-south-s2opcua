.. Images
.. |opcua_1| image:: images/opcua_1.jpg
.. |opcua_2| image:: images/opcua_2.jpg
.. |opcua_3| image:: images/opcua_3.jpg
.. |opcua_4| image:: images/opcua_4.jpg

.. |UaExpert| raw:: html

    <a href="https://www.unified-automation.com/downloads/opc-ua-clients.html">Ua Expert</a>

.. |S2OPCUA| raw:: html

    <a href="https://www.s2opc.com">S<sup>2</sup>OPC safe &amp; secure</a>

.. |generate_certs| raw:: html

    <a href="https://gitlab.com/systerel/S2OPC/-/blob/master/samples/ClientServer/data/cert/generate_certs.sh"><code>generate_certs.sh</code> example script</a>

OPC/UA Safe & Secure South Plugin
=================================

The *fledge-south-s2opcua* plugin allows Fledge to connect to an OPC/UA server and subscribe to changes in the objects within the OPC/UA server. This plugin is very similar to the *fledge-south-opcua* plugin but is implemented using a different underlying OPC/UA open source library, |S2OPCUA| from Systerel. The major difference between the two is the ability of this plugin to support secure endpoints with the OPC/UA server.

A south service to collect OPC/UA data is created in the same way as any other south service in Fledge.

  - Use the *South* option in the left hand menu bar to display a list of your South services

  - Click on the + add icon at the top right of the page

  - Select the *s2opcua* plugin from the list of plugins you are provided with

  - Enter a name for your south service

  - Click on *Next* to configure the OPC/UA plugin

+-----------+
| |opcua_1| |
+-----------+

The configuration parameters that can be set on this page are;

  - **Asset Name**: This is a prefix that will be applied to all assets that are created by this plugin. The OPC/UA plugin creates a separate asset for each data item read from the OPC/UA server. This is done since the OPC/UA server will deliver changes to individual data items only. Combining these into a complex asset would result in assets that do only contain one of many data points in each update. This can cause upstream systems problems with the every changing asset structure.

  - **OPCUA Server URL**: This is the URL of the OPC/UA server from which data will be extracted. The URL should be of the form opc.tcp://..../

  - **OPCUA Object Subscriptions**: The subscriptions are a set of locations in the OPC/UA object hierarchy that defined which data is subscribed to in the server and hence what assets get created within Fledge. A fuller description of how to configure subscriptions is shown below.

  - **Min Reporting Interval**: This control the minimum interval between reports of data changes in subscriptions. It sets an upper limit to the rate that data will be ingested into the plugin and is expressed in milliseconds.

    +-----------+
    | |opcua_2| |
    +-----------+

  - **Security Mode**: Specify the OPC/UA security mode that will be used to communicate with the OPC/UA server.

    +-----------+
    | |opcua_3| |
    +-----------+

  - **Security Policy**: Specify the OPC/UA security policy that will be used to communicate with the OPC/UA server.

    +-----------+
    | |opcua_4| |
    +-----------+

  - **User authentication policy**: Specify the user authentication policy that will be used when authenticating the connection to the OPC/UA server.

  - **Username**: Specify the username to use for authentication. This is only used if the *User authentication policy* is set to *username*.

  - **Password**: Specify the password to use for authentication. This is only used if the *User authentication policy* is set to *username*.

  - **CA certificate authority**: The name of the root certificate authorities certificate in DER format. This is the certificate authority that forms the root of trust and signs the certificates that will be trusted.

  - **Server public key**: The name of the public key of the OPC/UA server specified in the *OPCUA Server URL*. This should be a DER format certificate signed by the certificate authority.

  - **Client public key**: The name of the public key of the client application, i.e. the key to use for this plugin. This should be a DER format certificate signed by the certificate authority.

  - **Client private key**: The name of the private key of the client application, i.e. the private key the plugin will use. This should be a PEM format key.

  - **Certificate revocation list**: The name of the certificate authority's Certificate Revocation List. This is a DER format certificate.

Subscriptions
-------------

Subscriptions to OPC/UA objects are stored as a JSON object that contents an array named "subscriptions". This  array is a set of OPC/UA nodes that will control the subscription to variables in the OPC/UA server. Each element in the array is an OPC/UA node id, if that node is is the id of a variable then that single variable will be added to the subscription list. If the node id is not a visible, then the plugin will recurse down the object tree below that node and add every variable in finds in this tree to the subscription list.

A subscription list which gives the root node of the OPC/UA server will cause all variables within the server to be added to the subscription list. Care however should be taken as this may be a large number of assets.

Subscription examples
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

    {"subscriptions":["5:Simulation","2:MyLevel"]}

We subscribe to

 - 5:Simulation is a node name under ObjectsNode in namespace 5

 - 2:MyLevel is a variable under ObjectsNode in namespace 2

.. code-block:: console

    {"subscriptions":["5:Sinusoid1","2:MyLevel","5:Sawtooth1"]}


We subscribe to

 - 5:Sinusoid1 and 5:Sawtooth1 are variables under ObjectsNode/Simulation in namespace 5

 - 2:MyLevel is a variable under ObjectsNode in namespace 2

.. code-block:: console

    {"subscriptions":["2:Random.Double","2:Random.Boolean"]}

We subscribe to

 - Random.Double and Random.Boolean are variables under ObjectsNode/Demo both in namespace 2

Object names, variable names and namespace indices can be easily retrieved browsing the given OPC/UA server using OPC UA clients, such as |UaExpert|.

Certificate Management
----------------------

The configuration described above uses the names of certificates that will be used by the plugin, these certificates must be loaded into the Fledge certificate store as a manual process and named to match the names used in the configuration before the plugin is started.

Typically the certificate authorities certificate is retrieved and uploaded to the certificate store along with the certificate from the OPC/UA server that has been signed by that certificate authority. A public/private key pair must also be created for the plugin and signed by the certificate authority. These are uploaded to the Fledge certificate store.

Openssl may be used to generate and convert the keys and certificates required, an |generate_certs| to do this is available as part of the underlying |S2OPCUA| library.
