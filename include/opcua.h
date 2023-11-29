#ifndef _OPCUA_H
#define _OPCUA_H
/*
 * Fledge S2OPCUA South service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora, Mark Riddoch
 */
#include <string>
#include <atomic>
#include <config_category.h>
#include <reading.h>
#include <logger.h>
#include <utils.h>
#include <mutex>
#include <thread>
#include <stdlib.h>
#include <sys/time.h>
#include <map>
#include <set>
extern "C" {
#include "sopc_logger.h"
#include "libs2opc_common_config.h"
#include "libs2opc_client_cmds.h"
#include "sopc_logger.h"
#include "sopc_time.h"
};

class OpcUaClient;

/* Lifetime Count of subscriptions */
#define MAX_LIFETIME_COUNT 1000
/* Number of targeted publish token */
#define PUBLISH_N_TOKEN 2
/* Connection global timeout */
#define TIMEOUT_MS 10000
/* Secure Channel lifetime */
#define SC_LIFETIME_MS 3600000

/**
 * Interface to the S2 OPCUA library
 */
class OPCUA
{
    public:
        OPCUA();
        ~OPCUA();
        void        clearConfig();
        void        clearData();
        bool        isRegexValid(const std::string &regex);
        void        parseConfig(ConfigCategory &config);
        void        reconfigure(ConfigCategory &config);
        void        clearSubscription();
        void        addSubscription(const std::string& parent);
        int         addSubscriptions(std::vector<std::string> vec);
        void        getEndpoints();
        void        setAssetName(const std::string& name);
        void        newURL(const std::string& url) { m_url = url; };
        void        start();
        void        stop();
        void        ingest(std::vector<Datapoint *> points, const timeval& user_ts, const std::string& parent = "");
        void        setReportingInterval(long value);
        void        registerIngest(void *data, void (*cb)(void *, Reading))
                {
                    m_ingest = cb;
                    m_data = data;
                }
        void        setSecMode(const std::string& secMode);
        void        setSecPolicy(const std::string& secPolicy);
        void        setAuthPolicy(const std::string& authPolicy) { m_authPolicy = authPolicy; }
        void        setUsername(const std::string& username) { m_username = username; }
        void        setPassword(const std::string& password) { m_password = password; }
        void        setCaCert(const std::string& cert) { m_certAuth = cert; }
        void        setServerCert(const std::string& cert) { m_serverPublic = cert; }
        void        setClientCert(const std::string& cert) { m_clientPublic = cert; }
        void        setClientKey(const std::string& key) { m_clientPrivate = key; }
        void        setRevocationList(const std::string& cert) { m_caCrl = cert; }
        void        setTraceFile(const std::string& traceFile);
        void        setAssetNaming(const std::string& scheme);
	void        dataChange(const char *nodeId, const SOPC_DataValue *value);
	void	    disconnect(const uint32_t connectionId);
	void	    retry();
    private:

	class Node
	{
		public:
				Node(uint32_t connId, const std::string& nodeId);
				Node(const std::string& nodeId, const std::string& BrowseName);
				std::string	getBrowseName() { return m_browseName; };
				uint32_t	getType() { return m_type; };
				std::string	getNodeId() { return m_nodeID; };
				OpcUa_NodeClass	getNodeClass() { return m_nodeClass; };
				void		duplicateBrowseName();
		private:
				const std::string	m_nodeID;
				std::string		m_browseName;
				uint32_t		m_type;
				OpcUa_NodeClass		m_nodeClass;
	};
    private:
        int         		subscribe();
	void			browse(const std::string& nodeId, std::vector<std::string>&);
    void            getNodeFullPath(const std::string &nodeId, std::string& path);
    void            setRetryThread(bool start);
	SOPC_ClientHelper_GetEndpointsResult
				*GetEndPoints(const char *endPointUrl);
	std::string		securityMode(OpcUa_MessageSecurityMode mode);
	std::string		nodeClassStr(OpcUa_NodeClass nodeClass);
	void			resolveDuplicateBrowseNames();
	bool 			checkFiltering(const std::string& browseName, OpcUa_NodeClass nodeClass, bool isDirectlySubscribed=false);
	
	// void			getParents();
	int32_t			m_connectionId;
	int32_t			m_configurationId;
        std::vector<std::string>
				m_subscriptions;	// The user subscriptions
	std::map<std::string, Node *>
				m_nodes;		// The nodes being monitored
        std::string            	m_url;
        std::string            	m_asset;
        void                	(*m_ingest)(void *, Reading);
        void                	*m_data;
        std::mutex            	m_configMutex;
        std::atomic<bool>       m_connected;
        long                	m_reportingInterval;
        unsigned long           m_numOpcUaValues;
        unsigned long           m_numOpcUaOverflows;

        std::string         	m_secPolicy;
        OpcUa_MessageSecurityMode m_secMode;

        std::string            	m_authPolicy;
        std::string            	m_username;
        std::string         	m_password;
        
        std::string            	m_serverPublic;
        std::string            	m_clientPublic;
        std::string            	m_clientPrivate;
        std::string            	m_certAuth;
        std::string            	m_caCrl;
        
        int64_t             	m_publishPeriod;
        uint16_t             	m_tokenTarget;
        int                 	m_nodeIdsSize;
		
        bool                 	m_disableCertVerif;
        char                 	*m_traceFile;
        uint32_t             	m_maxKeepalive;
        bool                    m_includePathAsMetadata;
        std::string             m_metaDataName;
	char		    *m_path_cert_auth;
	char			*m_path_crl;
	char			*m_path_cert_srv;
	char			*m_path_cert_cli;
	char			*m_path_key_cli;
	std::atomic<bool> m_stopped;
	std::atomic<bool> m_readyForData;
	std::thread		*m_background;
	bool			m_init;
	std::map<std::string, struct timeval>
				m_lastIngest;
	enum {
		ASSET_NAME_SINGLE, ASSET_NAME_SINGLE_OBJ, ASSET_NAME_OBJECT, ASSET_NAME
				} m_assetNaming;
	std::set<Node *> m_nodeObjects;
    std::map<std::string, std::string>
				m_parents;	// Map variable node id to parent node id
	std::map<std::string, Node *>
				m_parentNodes;
	std::map<std::string, std::string>
				m_fullPaths; 	// Map variable node id to full OPC UA path

	bool				m_filterEnabled;
	std::string			m_filterRegex;

	enum NodeFilterScope {
		SCOPE_OBJECT=1,
		SCOPE_VARIABLE,
		SCOPE_OBJECT_VARIABLE,
		SCOPE_INVALID=0xff
		};
	NodeFilterScope		m_filterScope;

	enum NodeFilterAction {
		INCLUDE_NODES=1,
		EXCLUDE_NODES,
		ACTION_INVALID=0xff			
		};
	NodeFilterAction	m_filterAction;

	bool getFilterEnabled() { return m_filterEnabled; }
	void setFilterEnabled(bool val) { m_filterEnabled = val; }

	std::string getFilterRegex() { return m_filterRegex; }
	void setFilterRegex(std::string& val) { m_filterRegex = val; }

	NodeFilterScope getFilterScope() { return m_filterScope; }
	NodeFilterScope setFilterScope(std::string& val)
	{
		if(val.compare("Object")==0)
			m_filterScope = NodeFilterScope::SCOPE_OBJECT;
		else if(val.compare("Variable")==0)
			m_filterScope = NodeFilterScope::SCOPE_VARIABLE;
		else if(val.compare("Object and Variable")==0)
			m_filterScope = NodeFilterScope::SCOPE_OBJECT_VARIABLE;
		else
			return NodeFilterScope::SCOPE_INVALID;

		return m_filterScope;
	}

	std::string getFilterScopeStr()
	{
		switch(m_filterScope)
		{
			case NodeFilterScope::SCOPE_OBJECT: return "Object";
			case NodeFilterScope::SCOPE_VARIABLE: return "Variable";
			case NodeFilterScope::SCOPE_OBJECT_VARIABLE: return "Object and Variable";
			default: return "Invalid scope";
		}
	}

	NodeFilterAction getFilterAction() { return m_filterAction; }
	NodeFilterAction setFilterAction(std::string& val)
	{
		if(val.compare("Include nodes")==0)
			m_filterAction = NodeFilterAction::INCLUDE_NODES;
		else if(val.compare("Exclude nodes")==0)
			m_filterAction = NodeFilterAction::EXCLUDE_NODES;
		else
			return NodeFilterAction::ACTION_INVALID;

		return m_filterAction;
	}
	std::string getFilterActionStr()
	{
		switch(m_filterAction)
		{
			case NodeFilterAction::INCLUDE_NODES: return "Include nodes";
			case NodeFilterAction::EXCLUDE_NODES: return "Exclude nodes";
			default: return "Invalid action";
		}
	}
	
};

#endif
