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
#include <mutex>
#include <stdlib.h>
#include <map>
extern "C" {
#include "libs2opc_client_cmds.h"
};

class OpcUaClient;

/* Lifetime Count of subscriptions */
#define MAX_LIFETIME_COUNT 1000
/* Number of targetted publish token */
#define PUBLISH_N_TOKEN 2
/* Connection global timeout */
#define TIMEOUT_MS 10000
/* Secure Channel lifetime */
#define SC_LIFETIME_MS 3600000

/* Path to the certificate authority */
#define PATH_CACERT_PUBL "/home/nerd039/dev/S2OPC/bin/trusted/cacert.der"
/* Path to the CA CRL */
#define PATH_CACRL_PUBL "/home/nerd039/dev/S2OPC/bin/revoked/cacrl.der"
/* Path to the server certificate */
#define PATH_SERVER_PUBL "/home/nerd039/dev/S2OPC/bin/server_public/server_2k_cert.der"
/* Path to the client certificate */
#define PATH_CLIENT_PUBL "/home/nerd039/dev/S2OPC/bin/client_public/client_2k_cert.der"
/* Path to the client private key */
#define PATH_CLIENT_PRIV "/home/nerd039/dev/S2OPC/bin/client_private/client_2k_key.pem"

/*
typedef enum {
    SOPC_SecurityPolicy_None_URI,
    SOPC_SecurityPolicy_Basic256_URI,
    SOPC_SecurityPolicy_Basic256Sha256_URI
} SOPC_SecurityPolicy_type;
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
        void        ingest(std::vector<Datapoint *> points, long user_ts);
        void        setReportingInterval(long value);
        void        registerIngest(void *data, void (*cb)(void *, Reading))
                {
                    m_ingest = cb;
                    m_data = data;
                }
        void        setSecMode(const std::string& secMode);
        void        setSecPolicy(const std::string& secPolicy);
        void        setAuthPolicy(const std::string& authPolicy)
       			{
				std::lock_guard<std::mutex> guard(m_configMutex);
				m_authPolicy = authPolicy;
			}
        void        setUsername(const std::string& username)
			{
				std::lock_guard<std::mutex> guard(m_configMutex);
				m_username = username;
			}
        void        setPassword(const std::string& password)
			{
				std::lock_guard<std::mutex> guard(m_configMutex);
				m_password = password;
			}
        void        setCaCert(const std::string& cert)
			{
				std::lock_guard<std::mutex> guard(m_configMutex);
				m_certAuth = cert;
			}
        void        setServerCert(const std::string& cert)
			{
				std::lock_guard<std::mutex> guard(m_configMutex);
				m_serverPublic = cert;
			}
        void        setClientCert(const std::string& cert)
			{
				std::lock_guard<std::mutex> guard(m_configMutex);
				m_clientPublic = cert;
			}
        void        setClientKey(const std::string& key)
			{
				std::lock_guard<std::mutex> guard(m_configMutex);
				m_clientPrivate = key;
			}
        void        setRevocationList(const std::string& cert)
			{
				std::lock_guard<std::mutex> guard(m_configMutex);
				m_caCrl = cert;
			}
	void        dataChange(const char *nodeId, const SOPC_DataValue *value);
	void	    disconnect();
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
	std::string		securityMode(OpcUa_MessageSecurityMode mode);
	std::string		nodeClass(OpcUa_NodeClass nodeClass);
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
        uint32_t             	m_maxKeepalive;
	char			*m_path_cert_auth;
	char			*m_path_crl;
	char			*m_path_cert_srv;
	char			*m_path_cert_cli;
	char			*m_path_key_cli;
};

#endif
