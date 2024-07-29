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
#include "libs2opc_client_config_custom.h"
#include "libs2opc_new_client.h"
#include "libs2opc_request_builder.h"
#include "sopc_time.h"
#include "sopc_macros.h"
#include "sopc_mem_alloc.h"
#include "sopc_encodeable.h"
#include "opcua_identifiers.h"
#include "opcua_statuscodes.h"
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
/* Number of Variables to return for each browse call */
#define BROWSE_BLOCKSIZE 512

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
        void        setAssetName(const std::string& name);
		std::string	getInstanceName() { return m_instanceName; };
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
		void        setInstanceName(const std::string& instanceName) { m_instanceName = instanceName; };
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
		bool		readyForData() {return (!m_stopped.load() && m_readyForData.load());}
		void		incrementNothingToDo() {m_numOpcUaNothingToDo++;}
        std::string	&getUsername() { return m_username; }
        std::string	&getPassword() { return m_password; }

	void        dataChange(const char *nodeId, const SOPC_DataValue *value);
	void	    disconnect();
	void	    retry();
    private:

	class OPCUASecurity
	{
		public:
			OPCUASecurity();
			~OPCUASecurity();
			const char* security_policy;
			OpcUa_MessageSecurityMode security_mode;
			OpcUa_UserTokenType tokenType;
			char* userPolicyId;
	};

	class Node
	{
		public:
				Node(SOPC_ClientConnection *connection, const std::string& nodeId);
				Node(const std::string& nodeId, const std::string& BrowseName);
				std::string	getBrowseName() { return m_browseName; };
				std::string	getNodeId() { return m_nodeID; };
				OpcUa_NodeClass	getNodeClass() { return m_nodeClass; };
				void		duplicateBrowseName();
		private:
				const std::string	m_nodeID;
				std::string		m_browseName;
				OpcUa_NodeClass		m_nodeClass;
	};
    private:
        int         		subscribe();
	SOPC_ReturnStatus	initializeS2sdk(const char *traceFilePath);
	void				uninitializeS2sdk();
	SOPC_ReturnStatus	createS2Subscription();
	SOPC_ReturnStatus	deleteS2Subscription();
	SOPC_ReturnStatus	createS2MonitoredItems(char *const *nodeIds, const size_t numNodeIds, bool logRevisions, size_t *numErrors);
	void			browseVariables(const std::string& nodeId, std::vector<std::string>&);
	void			browseObjects(const std::string& nodeId, std::set<string> &objectNodeIds);
    void            getNodeFullPath(const std::string &nodeId, std::string& path);
    void            setRetryThread(bool start);
	OpcUa_GetEndpointsResponse
				*GetEndPoints(const char *endPointUrl);
	std::string		securityMode(OpcUa_MessageSecurityMode mode);
	std::string		nodeClassStr(OpcUa_NodeClass nodeClass);
	void			resolveDuplicateBrowseNames();
	bool 			checkFiltering(const std::string& browseName, OpcUa_NodeClass nodeClass, bool isDirectlySubscribed=false);
	bool			writeS2ConfigXML(const std::string &xmlFilePath, const OPCUASecurity &security,
						const std::string &clientPublic,
						const std::string &clientKey,
						const std::string &serverPublic);
	
	SOPC_ClientConnection *m_connection;
	SOPC_ClientHelper_Subscription *m_subscription;
	char 			**m_nodeIds;
	size_t			m_numNodeIds;
        std::vector<std::string>
				m_subscriptions;	// The user subscriptions
	std::map<std::string, Node *>
				m_nodes;		// The nodes being monitored
        std::string            	m_url;
        std::string            	m_asset;
		std::string				m_instanceName;
        void                	(*m_ingest)(void *, Reading);
        void                	*m_data;
        std::mutex            	m_configMutex;
        std::atomic<bool>       m_connected;
        long                	m_reportingInterval;
        unsigned long           m_numOpcUaValues;
        unsigned long           m_numOpcUaOverflows;
        unsigned long           m_numOpcUaNothingToDo;

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
        int                 	m_nodeIdsSize;
        int                 	m_miBlockSize;
		
        char                 	*m_traceFile;
        uint32_t             	m_maxKeepalive;
        bool                    m_includePathAsMetadata;
        std::string             m_metaDataName;
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
	time_t				m_tstart;
	unsigned long		m_totalElapsedSeconds;
	bool				m_dcfEnabled;
	OpcUa_DataChangeTrigger	m_dcfTriggerType;
	OpcUa_DeadbandType		m_dcfDeadbandType;
	double				m_dcfDeadbandValue;

	enum NodeFilterScope {
		SCOPE_OBJECT=1,
		SCOPE_VARIABLE,
		SCOPE_OBJECT_VARIABLE,
		SCOPE_INVALID=0xff
		};
	NodeFilterScope		m_filterScope;

	enum NodeFilterAction {
		INCLUDE=1,
		EXCLUDE,
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
		if(val.compare("Include")==0)
			m_filterAction = NodeFilterAction::INCLUDE;
		else if(val.compare("Exclude")==0)
			m_filterAction = NodeFilterAction::EXCLUDE;
		else
			return NodeFilterAction::ACTION_INVALID;

		return m_filterAction;
	}
	std::string getFilterActionStr()
	{
		switch(m_filterAction)
		{
			case NodeFilterAction::INCLUDE: return "Include";
			case NodeFilterAction::EXCLUDE: return "Exclude";
			default: return "Invalid action";
		}
	}
	
};

#endif
