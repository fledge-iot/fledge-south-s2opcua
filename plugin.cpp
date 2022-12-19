/*
 * Fledge south plugin.
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
#include <config_category.h>
#include <rapidjson/document.h>
#include <version.h>

typedef void (*INGEST_CB)(void *, Reading);

using namespace std;

#define PLUGIN_NAME    "s2opcua"

extern "C" {
void parse_config(OPCUA *opcua, ConfigCategory &config, bool reconf);
};

/**
 * Default configuration
 */
static const char *default_config = QUOTE({
    "plugin" : {
           "description" : "Simple OPC UA data change plugin",
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
            "displayName" : "OPCUA Server URL",
            "order" : "2"
            },
    "subscription" : {
            "description" : "Variables to observe changes in",
            "type" : "JSON",
            "default" : "{ \"subscriptions\" : [  \"ns=3;i=1001\", \"ns=3;i=1002\" ] }",
            "displayName" : "OPCUA Object Subscriptions",
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
	    "group" : "OPCUA Security",
            "order" : "7"
            },
    "securityPolicy" : {
            "description" : "Security Policy to use while connecting to OPCUA server" ,
            "type" : "enumeration",
            "options":["None", "Basic256", "Basic256Sha256"],
            "default" : "None",
            "displayName" : "Security Policy",
            "order" : "8",
	    "group" : "OPCUA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "userAuthPolicy" : {
            "description" : "User authentication policy to use while connecting to OPCUA server" ,
            "type" : "enumeration",
            "options":["anonymous", "username"],
            "default" : "anonymous",
            "displayName" : "User Authentication Policy",
	    "group" : "OPCUA Security",
            "order" : "9"
            },
    "username" : {
            "description" : "Username" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Username",
            "order" : "10",
	    "group" : "OPCUA Security",
            "validity": " userAuthPolicy == \"username\" "
            },
    "password" : {
            "description" : "Password" ,
            "type" : "password",
            "default" : "",
            "displayName" : "Password",
            "order" : "11",
	    "group" : "OPCUA Security",
            "validity": " userAuthPolicy == \"username\" "
            },
    "caCert" : {
            "description" : "Certificate Authority file in DER format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "CA Certificate Authority",
            "order" : "12",
	    "group" : "OPCUA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "serverCert" : {
            "description" : "Server certificate file in DER format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Server Public Certificate",
            "order" : "13",
	    "group" : "OPCUA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "clientCert" : {
            "description" : "Client certificate file in DER format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Client Public Certificate",
            "order" : "14",
	    "group" : "OPCUA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "clientKey" : {
            "description" : "Client private key file in PEM format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Client Private Key",
            "order" : "15",
	    "group" : "OPCUA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "caCrl" : {
            "description" : "Certificate Revocation List file in DER format" ,
            "type" : "string",
            "default" : "",
            "displayName" : "Certificate Revocation List",
            "order" : "16",
	    "group" : "OPCUA Security",
            "validity": " securityMode == \"Sign\" || securityMode == \"SignAndEncrypt\" "
            },
    "traceFile" : {
            "description" : "Enable trace file for debugging" ,
            "type" : "boolean",
            "default" : "false",
            "displayName" : "Debug Trace File",
	    "group" : "Advanced",
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
 */
PLUGIN_HANDLE plugin_init(ConfigCategory *config)
{
OPCUA    *opcua;
string    url;


    if (config->itemExists("url"))
    {
        url = config->getValue("url");
        opcua = new OPCUA(url);
    }
    else
    {
        Logger::getLogger()->fatal("OPC UA plugin is missing a URL");
        throw exception();
    }
    parse_config(opcua, *config, false);

    return (PLUGIN_HANDLE)opcua;
}

/**
 * Parse configuration
 */
void parse_config(OPCUA *opcua, ConfigCategory &config, bool reconf)
{
    if (reconf==true && config.itemExists("url"))
    {
        string url = config.getValue("url");
        opcua->newURL(url);
    }

    if (config.itemExists("asset"))
    {
        opcua->setAssetName(config.getValue("asset"));
    }

    if (config.itemExists("assetNaming"))
    {
        opcua->setAssetNaming(config.getValue("assetNaming"));
    }

    if (config.itemExists("reportingInterval"))
    {
        long val = strtol(config.getValue("reportingInterval").c_str(), NULL, 10);
        opcua->setReportingInterval(val);
    }
    else
    {
        opcua->setReportingInterval(100);
    }

    if (config.itemExists("subscription"))
    {
        // Now add the subscription data
        string map = config.getValue("subscription");
        rapidjson::Document doc;
        doc.Parse(map.c_str());
        if (!doc.HasParseError())
        {
            opcua->clearSubscription();
            if (doc.HasMember("subscriptions") && doc["subscriptions"].IsArray())
            {
                const rapidjson::Value& subs = doc["subscriptions"];
                for (rapidjson::SizeType i = 0; i < subs.Size(); i++)
                {
                    Logger::getLogger()->info("%s: Adding subscription for node id %d = '%s'", reconf?"RECONF":"INIT", i, subs[i].GetString());
                    opcua->addSubscription(subs[i].GetString());
                }
            }
            else
            {
                Logger::getLogger()->fatal("OPC UA plugin is missing a subscriptions array");
                throw exception();
            }
        }
    }

    if (config.itemExists("securityMode"))
    {
        opcua->setSecMode(config.getValue("securityMode"));
    }

    std::string secPolicy;
    if (config.itemExists("securityPolicy"))
    {
        secPolicy = config.getValue("securityPolicy");
        if(secPolicy.compare("None")==0 || secPolicy.compare("Basic256")==0 || secPolicy.compare("Basic256Sha256")==0)
            opcua->setSecPolicy(secPolicy);
        else
            throw exception();
    }

    if (config.itemExists("userAuthPolicy"))
    {
        std::string authPolicy = config.getValue("userAuthPolicy");
        opcua->setAuthPolicy(authPolicy);
    }

    if (config.itemExists("username"))
    {
        opcua->setUsername(config.getValue("username"));
    }

    if (config.itemExists("password"))
    {
        opcua->setPassword(config.getValue("password"));
    }

    if (config.itemExists("caCert"))
    {
        opcua->setCaCert(config.getValue("caCert"));
    }

    if (config.itemExists("serverCert"))
    {
        opcua->setServerCert(config.getValue("serverCert"));
    }

    if (config.itemExists("clientCert"))
    {
        opcua->setClientCert(config.getValue("clientCert"));
    }

    if (config.itemExists("clientKey"))
    {
        opcua->setClientKey(config.getValue("clientKey"));
    }

    if (config.itemExists("caCrl"))
    {
        opcua->setRevocationList(config.getValue("caCrl"));
    }

    if (config.itemExists("traceFile"))
    {
        opcua->setTraceFile(config.getValue("traceFile"));
    }
}

/**
 * Start the Async handling for the plugin
 */
void plugin_start(PLUGIN_HANDLE *handle)
{
    OPCUA *opcua = (OPCUA *)handle;

    if (!handle)
        return;
    
    opcua->start();
}

/**
 * Register ingest callback
 */
void plugin_register_ingest(PLUGIN_HANDLE *handle, INGEST_CB cb, void *data)
{
OPCUA *opcua = (OPCUA *)handle;

    if (!handle)
        throw new exception();
    opcua->registerIngest(data, cb);
}

/**
 * Poll for a plugin reading
 */
Reading plugin_poll(PLUGIN_HANDLE *handle)
{
OPCUA *opcua = (OPCUA *)handle;

    throw runtime_error("OPC UA is an async plugin, poll should not be called");
}

/**
 * Reconfigure the plugin
 *
 */
void plugin_reconfigure(PLUGIN_HANDLE *handle, string& newConfig)
{
ConfigCategory    config("new", newConfig);
OPCUA        *opcua = (OPCUA *)*handle;

    opcua->stop();
    parse_config(opcua, config, true);
    Logger::getLogger()->info("OPC UA plugin restart in progress...");
    opcua->start();
    Logger::getLogger()->info("OPC UA plugin restarted after reconfigure");
}

/**
 * Shutdown the plugin
 */
void plugin_shutdown(PLUGIN_HANDLE *handle)
{
OPCUA *opcua = (OPCUA *)handle;

    opcua->stop();
    delete opcua;
}
};

