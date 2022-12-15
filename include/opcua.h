#ifndef _OPCUA_H
#define _OPCUA_H
/*
 * Fledge south service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora, Mark Riddoch
 */
#include <string>
#include <reading.h>
#include <logger.h>
#include <utils.h>
#include <mutex>
#include <thread>
#include <stdlib.h>
#include <sys/time.h>
#include <map>
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
        OPCUA(const std::string& url);
        ~OPCUA();
        void        clearSubscription();
        void        addSubscription(const std::string& parent);
        int         addSubscriptions(std::vector<std::string> vec);
        void        getEndpoints();
        void        setAssetName(const std::string& name);
        void        restart();
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
				std::string	getBrowseName() { return m_browseName; };
				uint32_t	getType() { return m_type; };
				std::string	getNodeId() { return m_nodeID; };
				OpcUa_NodeClass	getNodeClass() { return m_nodeClass; };
		private:
				const std::string	m_nodeID;
				std::string		m_browseName;
				uint32_t		m_type;
				OpcUa_NodeClass		m_nodeClass;
	};
    private:
        int         		subscribe();
	void			browse(const std::string& nodeId, std::vector<std::string>&);
	SOPC_ClientHelper_GetEndpointsResult
				*GetEndPoints(const char *endPointUrl);
	std::string		securityMode(OpcUa_MessageSecurityMode mode);
	std::string		nodeClass(OpcUa_NodeClass nodeClass);
	void			getParents();
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
        bool                	m_connected;
        long                	m_reportingInterval;
        
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
	char			*m_path_cert_auth;
	char			*m_path_crl;
	char			*m_path_cert_srv;
	char			*m_path_cert_cli;
	char			*m_path_key_cli;
	bool			m_stopped;
	std::thread		*m_background;
	bool			m_init;
	std::map<std::string, struct timeval>
				m_lastIngest;
	enum {
		ASSET_NAME_SINGLE, ASSET_NAME_SINGLE_OBJ, ASSET_NAME_OBJECT, ASSET_NAME
				} m_assetNaming;
	std::map<std::string, std::string>
				m_parents;	// Map variable node id to parent node id
	std::map<std::string, Node *>
				m_parentNodes;
};

#endif
