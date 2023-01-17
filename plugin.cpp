/*
 * Fledge S2OPCUA South service plugin.
 *
 * Copyright (c) 2018 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Mark Riddoch
 */
#include <opcua.h>
#undef QUOTE    // S2OPC Toolkit has its own definition of QUOTE which conflicts with Fledge
#include <plugin_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string>
#include <logger.h>
#include <plugin_exception.h>
#include <rapidjson/document.h>
#include <version.h>

typedef void (*INGEST_CB)(void *, Reading);

using namespace std;

#define PLUGIN_NAME    "s2opcua"

/**
 * Default configuration
 */
static const char *default_config = QUOTE({
    "plugin" : {
           "description" : "Safe & Secure OPC UA data change plugin",
            "type" : "string",
            "default" : PLUGIN_NAME,
            "readonly" : "true"
            },
    "asset" : {
           "description" : "Asset name",
            "type" : "string",
            "default" : "s2opcua",
            "displayName" : "Asset Name",
            "order" : "1",
            "mandatory": "true"
            },
    "url" : {
            "description" : "URL of the OPC UA Server",
            "type" : "string",
            "default" : "opc.tcp://localhost:53530/OPCUA/SimulationServer",
            "displayName" : "OPC UA Server URL",
            "order" : "2"
            },
    "subscription" : {
            "description" : "Variables to observe changes in",
            "type" : "JSON",
            "default" : "{ \"subscriptions\" : [  \"ns=3;i=1001\", \"ns=3;i=1002\" ] }",
            "displayName" : "OPC UA Object Subscriptions",
            "order" : "3"
            },
    "reportingInterval" : {
            "description" : "The minimum reporting interval for data change notifications" ,
            "type" : "integer",
            "default" : "1000",
            "displayName" : "Min Reporting Interval (millisec)",
            "order" : "5"
            },
    "assetNaming" : {
            "description" : "The naming scheme to use for asset read from the OPCUA server. One or more assets can be created based on a fixed prefix or the OPCUA object names.",
            "type" : "enumeration",
	    "options" : [ "Single datapoint", "Single datapoint object prefix", "Asset per object", "Single asset" ],
            "default" : "Single datapoint",
            "displayName" : "Asset Naming Scheme",
            "order" : "6"
            },
    "securityMode" : {
            "description" : "Security Mode to use while connecting to OPCUA server" ,
            "type" : "enumeration",
            "options":["None", "Sign", "SignAndEncrypt"],
            "default" : "None",
            "displayName" : "Security Mode",
	    "group" : "OPC UA Security",
            "order" : "7"
            },
    "securityPolicy" : {
            "description" : "Security Policy to use while connecting to OPCUA server" ,
            "type" : "enumeration",
            "options":["None", "Basic256", "Basic256Sha256"],
            "default" : "None",
            "displayName" : "Security Policy",
            "order" : "8",
	    "group" : "OPC UA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "userAuthPolicy" : {
            "description" : "User authentication policy to use while connecting to OPCUA server" ,
            "type" : "enumeration",
            "options":["anonymous", "username"],
            "default" : "anonymous",
            "displayName" : "User Authentication Policy",
	    "group" : "OPC UA Security",
            "order" : "9"
            },
    "username" : {
            "description" : "Username" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Username",
            "order" : "10",
	    "group" : "OPC UA Security",
            "validity": " userAuthPolicy == \"username\" "
            },
    "password" : {
            "description" : "Password" ,
            "type" : "password",
            "default" : "",
            "displayName" : "Password",
            "order" : "11",
	    "group" : "OPC UA Security",
            "validity": " userAuthPolicy == \"username\" "
            },
    "caCert" : {
            "description" : "Certificate Authority file in DER format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "CA Certificate Authority",
            "order" : "12",
	    "group" : "OPC UA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "serverCert" : {
            "description" : "Server certificate file in DER format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Server Public Certificate",
            "order" : "13",
	    "group" : "OPC UA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "clientCert" : {
            "description" : "Client certificate file in DER format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Client Public Certificate",
            "order" : "14",
	    "group" : "OPC UA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "clientKey" : {
            "description" : "Client private key file in PEM format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Client Private Key",
            "order" : "15",
	    "group" : "OPC UA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "caCrl" : {
            "description" : "Certificate Revocation List file in DER format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Certificate Revocation List",
            "order" : "16",
	    "group" : "OPC UA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "traceFile" : {
            "description" : "Enable trace file for debugging" ,
            "type" : "boolean",
            "default" : "false",
            "displayName" : "Debug Trace File",
	    "group" : "OPC UA Advanced",
            "order" : "17"
            }
    });

/**
 * The OPCUA plugin interface
 */
extern "C" {

/**
 * The plugin information structure
 */
static PLUGIN_INFORMATION info = {
    PLUGIN_NAME,              // Name
    VERSION,                  // Version
    SP_ASYNC,           // Flags
    PLUGIN_TYPE_SOUTH,        // Type
    "1.0.0",                  // Interface version
    default_config          // Default configuration
};

/**
 * Return the information about this plugin
 */
PLUGIN_INFORMATION *plugin_info()
{
    Logger::getLogger()->info("OPC UA Config is %s", info.config);
    return &info;
}

/**
 * Initialise the plugin, called to get the plugin handle
 *
 * @param config    Plugin instance configuration
 * @return          Plugin handle
 */
PLUGIN_HANDLE plugin_init(ConfigCategory *config)
{
    OPCUA *opcua = new OPCUA();
    opcua->parseConfig(*config);
    return (PLUGIN_HANDLE)opcua;
}

/**
 * Start the Async handling for the plugin
 *
 * @param handle        The plugin handle
 */
void plugin_start(PLUGIN_HANDLE *handle)
{
    if (!handle)
        return;

    OPCUA *opcua = (OPCUA *)handle;
    opcua->start();
}

/**
 * Register ingest callback
 *
 * @param handle    The plugin handle
 * @param cb        Callback function pointer
 * @param data      Callback data pointer
 */
void plugin_register_ingest(PLUGIN_HANDLE *handle, INGEST_CB cb, void *data)
{
    OPCUA *opcua = (OPCUA *)handle;

    if (!handle)
        throw new exception();
    opcua->registerIngest(data, cb);
}

/**
 * Poll for a plugin reading (not used)
 *
 * @param handle     The plugin handle
 */
Reading plugin_poll(PLUGIN_HANDLE *handle)
{
    OPCUA *opcua = (OPCUA *)handle;
    throw runtime_error("OPC UA is an async plugin, poll should not be called");
}

/**
 * Reconfigure the plugin
 *
 * @param handle     The plugin handle
 * @param newConfig  Updated configuration as a JSON string
 */
void plugin_reconfigure(PLUGIN_HANDLE *handle, string &newConfig)
{
    ConfigCategory config("new", newConfig);
    OPCUA *opcua = (OPCUA *)*handle;
    opcua->reconfigure(config);
}

/**
 * Shutdown the plugin
 *
 * @param handle   The plugin handle
 */
void plugin_shutdown(PLUGIN_HANDLE *handle)
{
    OPCUA *opcua = (OPCUA *)handle;
    opcua->stop();
    delete opcua;
}
};
