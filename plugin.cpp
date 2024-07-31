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
                "description" : "Asset name. The Asset Naming Scheme determines how this name will be used.",
                "type" : "string",
                "default" : "s2opcua",
                "displayName" : "Asset Name",
                "order" : "1",
                "group" : "Basic",
                "mandatory" : "true"
        },
        "url" : {
                "description" : "URL of the OPC UA Server",
                "type" : "string",
                "default" : "opc.tcp://localhost:53530/OPCUA/SimulationServer",
                "displayName" : "OPC UA Server URL",
                "group" : "Basic",
                "order" : "2"
        },
        "assetNaming" : {
                "description" : "The naming scheme to use for asset read from the OPC UA server. One or more assets can be created based on a fixed prefix or the OPC UA object names.",
                "type" : "enumeration",
                "options" : [
                        "Single datapoint",
                        "Single datapoint object prefix",
                        "Asset per object",
                        "Single asset"
                ],
                "default" : "Single datapoint",
                "displayName" : "Asset Naming Scheme",
                "group" : "Basic",
                "order" : "3"
        },
        "subscription" : {
                "description" : "OPC UA Variables or Objects to observe for data changes",
                "type" : "JSON",
                "default" : "{ \"subscriptions\" : [  \"ns=3;i=1001\", \"ns=3;i=1002\" ] }",
                "displayName" : "OPC UA Node Subscriptions",
                "group" : "OPC UA Subscriptions",
                "order" : "11"
        },
        "filterRegex" : {
                "description" : "Regular expression for filtering OPC UA Objects or Variables by Browse Name",
                "type" : "string",
                "default" : "",
                "displayName" : "Name Filter Regular Expression",
                "group" : "OPC UA Subscriptions",
                "order" : "12"
        },
        "filterScope" : {
                "description" : "The type of object to apply the Browse Name filter",
                "type" : "enumeration",
                "options" : [
                        "Object",
                        "Variable",
                        "Object and Variable"
                ],
                "default" : "Variable",
                "displayName" : "Name Filter Scope",
                "order" : "13",
                "group" : "OPC UA Subscriptions"
        },
        "filterAction" : {
                "description" : "For Browse Names that match the filter, Include or Exclude the Objects or Variables",
                "type" : "enumeration",
                "options" : [
                        "Include",
                        "Exclude"
                ],
                "default" : "Exclude",
                "displayName" : "Name Filter Action",
                "order" : "14",
                "group" : "OPC UA Subscriptions"
        },
        "parentPathMetadata" : {
                "description" : "Include full OPC UA path as a Datapoint in a Fledge Reading",
                "type" : "boolean",
                "default" : "false",
                "displayName" : "Include Full OPC UA Path as meta data",
                "group" : "OPC UA Advanced",
                "order" : "21"
        },
        "parentPath" : {
                "description" : "Name for Full OPC UA Path meta data, if enabled",
                "type" : "string",
                "default" : "OPCUAPath",
                "displayName" : "Full OPC UA Path meta data name",
                "group" : "OPC UA Advanced",
                "order" : "22",
                "validity" : " parentPathMetadata == \"true\" "
        },
        "traceFile" : {
                "description" : "Enable trace file for debugging",
                "type" : "boolean",
                "default" : "false",
                "displayName" : "Debug Trace File",
                "group" : "OPC UA Advanced",
                "order" : "23"
        },
        "miBlockSize" : {
                "description" : "The number of MonitoredItems to be registered with the OPC UA server in single call to the S2OPC Toolkit",
                "type" : "integer",
                "default" : "100",
                "minimum" : "1",
                "displayName" : "MonitoredItem block size",
                "group" : "OPC UA Advanced",
                "order" : "24"
        },
        "reportingInterval" : {
                "description" : "The minimum reporting interval for data change notifications, in miliseconds",
                "type" : "integer",
                "default" : "0",
                "minimum" : "0",
                "displayName" : "Minimum Reporting Interval",
                "group" : "OPC UA Advanced",
                "order" : "25"
        },
        "dcfEnabled" : {
                "description" : "Enable OPC UA Data Change Filter",
                "type" : "boolean",
                "default" : "false",
                "displayName" : "Enable Data Change Filter",
                "order" : "26",
                "group" : "OPC UA Advanced"
        },
        "dcfTriggerType" : {
                "description" : "Type of data change that should cause a notification to be reported by the OPC UA server",
                "type" : "enumeration",
                "options" : [
                        "Status",
                        "Status + Value",
                        "Status + Value + Timestamp"
                ],
                "default" : "Status + Value",
                "displayName" : "Data Change Filter Trigger Type",
                "order" : "27",
                "validity" : " dcfEnabled == \"true\" ",
                "group" : "OPC UA Advanced"
        },
        "dcfDeadbandType" : {
                "description" : "Behavior of the Data Change Filter Deadband Value. If None, there is no deadband evaluation.",
                "type" : "enumeration",
                "options" : [
                        "None",
                        "Absolute",
                        "Percent"
                ],
                "default" : "None",
                "displayName" : "Data Change Filter Deadband Type",
                "order" : "28",
                "validity" : " dcfEnabled == \"true\" ",
                "group" : "OPC UA Advanced"
        },
        "dcfDeadbandValue" : {
                "description" : "Evaluated only if the Data Change Filter Deadband Type is 'Absolute' or 'Percent'",
                "type" : "float",
                "default" : "0",
                "minimum" : "0",
                "displayName" : "Data Change Filter Deadband Value",
                "order" : "29",
                "validity" : " dcfEnabled == \"true\" ",
                "group" : "OPC UA Advanced"
        },
        "securityMode" : {
                "description" : "Security Mode to use while connecting to OPC UA server",
                "type" : "enumeration",
                "options" : [
                        "None",
                        "Sign",
                        "SignAndEncrypt"
                ],
                "default" : "None",
                "displayName" : "Security Mode",
                "group" : "OPC UA Security",
                "order" : "31"
        },
        "securityPolicy" : {
                "description" : "Security Policy to use while connecting to OPC UA server",
                "type" : "enumeration",
                "options" : [
                        "None",
                        "Basic256",
                        "Basic256Sha256"
                ],
                "default" : "None",
                "displayName" : "Security Policy",
                "order" : "32",
                "group" : "OPC UA Security",
                "validity" : " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
        },
        "userAuthPolicy" : {
                "description" : "User authentication policy to use while connecting to OPC UA server",
                "type" : "enumeration",
                "options" : [
                        "anonymous",
                        "username"
                ],
                "default" : "anonymous",
                "displayName" : "User Authentication Policy",
                "group" : "OPC UA Security",
                "order" : "33"
        },
        "username" : {
                "description" : "Username",
                "type" : "string",
                "default" : "",
                "displayName" : "Username",
                "order" : "34",
                "group" : "OPC UA Security",
                "validity" : " userAuthPolicy == \"username\" "
        },
        "password" : {
                "description" : "Password",
                "type" : "password",
                "default" : "",
                "displayName" : "Password",
                "order" : "35",
                "group" : "OPC UA Security",
                "validity" : " userAuthPolicy == \"username\" "
        },
        "caCert" : {
                "description" : "Certificate Authority file in DER format",
                "type" : "string",
                "default" : "",
                "displayName" : "CA Certificate Authority",
                "order" : "36",
                "group" : "OPC UA Security",
                "validity" : " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
        },
        "serverCert" : {
                "description" : "Server certificate file in DER format",
                "type" : "string",
                "default" : "",
                "displayName" : "Server Public Certificate",
                "order" : "37",
                "group" : "OPC UA Security",
                "validity" : " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
        },
        "clientCert" : {
                "description" : "Client certificate file in DER format",
                "type" : "string",
                "default" : "",
                "displayName" : "Client Public Certificate",
                "order" : "38",
                "group" : "OPC UA Security",
                "validity" : " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
        },
        "clientKey" : {
                "description" : "Client private key file in PEM format",
                "type" : "string",
                "default" : "",
                "displayName" : "Client Private Key",
                "order" : "39",
                "group" : "OPC UA Security",
                "validity" : " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
        },
        "caCrl" : {
                "description" : "Certificate Revocation List file in DER format",
                "type" : "string",
                "default" : "",
                "displayName" : "Certificate Revocation List",
                "order" : "40",
                "group" : "OPC UA Security",
                "validity" : " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
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
    opcua->setInstanceName(config->getName());
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
    OPCUA *opcua = (OPCUA *)*handle;
    ConfigCategory config(opcua->getInstanceName(), newConfig);
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
