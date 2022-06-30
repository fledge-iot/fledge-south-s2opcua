/*
 * Fledge south service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora
 */

#include <opcua.h>
#include <string.h>
#include <reading.h>
#include <logger.h>
#include <map>
#include <unistd.h>

using namespace std;

// Hold subscription variables
map<string, bool> subscriptionVariables;

static OPCUA *opcua = NULL;


/**
 * Callback function for a disconnection from the OPCUA server
 *
 * @param c_id	The conenction ID
 */
static void disconnect_callback(const uint32_t c_id)
{
	Logger::getLogger()->info("Client %u disconnected.", c_id);
	if (opcua)
	{
	    opcua->disconnect();
	}
}

/**
 * Callback function called when a change occurs in one of the nodes
 * that we have registered to receive changes.
 *
 * @param c_id	The connection id
 * @param d_id	The data id of the changed node
 * @param value	The new value of the node
 */
static void datachange_callback(const int32_t c_id,
                                const char *nodeId,
                                const SOPC_DataValue *value)
{
	if (opcua)
	{
	    opcua->dataChange(nodeId, value);
	}
}

/**
 * The retry thread entry point
 */
static void retryThread(void *data)
{
	((OPCUA *)data)->retry();
}

/**
 * Convert the user authentication Policy Id to OpcUa_UserTokenType
 *
 * @param policyId	PolicyId string: anonymous or username
 */
static OpcUa_UserTokenType PolicyIdToUserTokenType(const char *policyId)
{
	if (policyId && strlen(policyId))
	{
		char anonymous[] ="anonymous";
		char username[] ="username";

		if (!strncmp(policyId, anonymous, strlen(anonymous)))
		{
			return OpcUa_UserTokenType_Anonymous;
		}
		else if (!strncmp(policyId, username, strlen(username)))
		{
			return OpcUa_UserTokenType_UserName;
		}
		else
		{
			return OpcUa_UserTokenType_SizeOf; // use this token type as an error condition
		}
	}
	else
	{
		return OpcUa_UserTokenType_SizeOf; // use this token type as an error condition
	}
}

/**
 * A data value we are monitoring has changed
 *
 * @param nodeId	The ID of the node that has changed
 * @param value		The new vlaue of the node
 */
void OPCUA::dataChange(const char *nodeId, const SOPC_DataValue *value)
{
DatapointValue* dpv = NULL;

	if (m_background && m_background->joinable())	// Collect the background thread
	{
		m_background->join();
		m_background = NULL;
	}
	Logger::getLogger()->debug("Data change call for node %s", nodeId);
	if (value)
	{
		SOPC_Variant variant = value->Value;
		if (variant.ArrayType == SOPC_VariantArrayType_SingleValue)
		{
			switch (variant.BuiltInTypeId)
			{
				case SOPC_UInt64_Id:
					dpv = new DatapointValue((long)variant.Value.Uint64);
					break;
				case SOPC_Int64_Id:
					dpv = new DatapointValue((long)variant.Value.Uint64);
					break;
				case SOPC_UInt32_Id:
					dpv = new DatapointValue((long)(variant.Value.Uint32));
					break;
				case SOPC_Int32_Id:
					dpv = new DatapointValue((long)(variant.Value.Uint32));
					break;
				case SOPC_UInt16_Id:
					dpv = new DatapointValue((long)(variant.Value.Uint16));
					break;
				case SOPC_Int16_Id:
					dpv = new DatapointValue((long)(variant.Value.Uint16));
					break;
				case SOPC_Boolean_Id:
					dpv = new DatapointValue((long)(variant.Value.Boolean));
					break;
				case SOPC_Byte_Id:
					dpv = new DatapointValue((double)(variant.Value.Byte));
					break;
				case SOPC_SByte_Id:
					dpv = new DatapointValue((double)(variant.Value.Sbyte));
					break;
				case SOPC_Float_Id:
					dpv = new DatapointValue((double)(variant.Value.Floatv));
					break;
				case SOPC_Double_Id:
					dpv = new DatapointValue((double)(variant.Value.Doublev));
					break;
				case SOPC_String_Id:
				{
					string str = SOPC_String_GetRawCString(&variant.Value.String);
					dpv = new DatapointValue(str);
					break;
				}
				case SOPC_ByteString_Id:
					Logger::getLogger()->warn("Unable to handle ByteStrings currently");
					break;
				case SOPC_Null_Id:
					Logger::getLogger()->warn("Unable to handle items with Null type");
					break;
				default:
					Logger::getLogger()->warn("Unable to determine type %d", variant.BuiltInTypeId);
					break;
			}
		}
		else if (variant.ArrayType == SOPC_VariantArrayType_Array)
		{
			// TODO Support Array types
			Logger::getLogger()->error("Array types not supported");
		}
		else if (variant.ArrayType == SOPC_VariantArrayType_Matrix)
		{
			Logger::getLogger()->error("Change in matrix type node %s, matrices not supported",
					nodeId);
		}
		else
		{
			Logger::getLogger()->error("Unable to determine array type");
		}

    		if (dpv)
		{
			vector<Datapoint *>    points;
			string dpname = nodeId;
			auto res = m_nodes.find(nodeId);
			if (res != m_nodes.end())
			{
				dpname = res->second->getBrowseName();
			}
			// Strip " from datapoint name
			size_t pos;
			while ((pos = dpname.find_first_of("\"")) != std::string::npos)
			{
				dpname.erase(pos, 1);
			}
			points.push_back(new Datapoint(dpname, *dpv));
			ingest(points, 0);
		}
	}
}


/**
 * Constructor for the opcua plugin
 */
OPCUA::OPCUA(const string& url) : m_url(url), 
				m_connected(false), m_publishPeriod(1000),
				m_maxKeepalive(30), m_tokenTarget(1),
				m_disableCertVerif(false),
				m_path_cert_auth(NULL),
				m_path_crl(NULL),
				m_path_cert_srv(NULL),
				m_path_cert_cli(NULL),
				m_path_key_cli(NULL),
				m_stopped(false),
				m_background(NULL),
				m_init(false),
				m_traceFile(NULL)
{
	opcua = this;
}

/**
 * Destructor for the opcua interface
 */
OPCUA::~OPCUA()
{
}

/**
 * Set the asset name for the asset we write
 *
 * @param asset Set the name of the asset with insert into readings
 */
void
OPCUA::setAssetName(const std::string& asset)
{
	m_asset = asset;
}

/**
 * Set the minimum interval between data change events for subscriptions
 *
 * @param value    Interval in milliseconds
 */
void
OPCUA::setReportingInterval(long value)
{
	m_reportingInterval = value;
}

/**
 * Set the message security mode
 *
 * @param value    Security mode string
 */
void
OPCUA::setSecMode(const std::string& secMode)
{ 
	if (secMode.compare("None") == 0)
		m_secMode = OpcUa_MessageSecurityMode_None;
	else if (secMode.compare("Sign") == 0)
		m_secMode = OpcUa_MessageSecurityMode_Sign;
	else if (secMode.compare("SignAndEncrypt") == 0)
		m_secMode = OpcUa_MessageSecurityMode_SignAndEncrypt;
	else 
	{
		m_secMode = OpcUa_MessageSecurityMode_Invalid;
		Logger::getLogger()->error("Invalid Security mode '%s'", secMode.c_str());
	}
}

/**
 * Set the security policy
 *
 * @param value    Security policy string
 */
void
OPCUA::setSecPolicy(const std::string& secPolicy)
{
	if (!secPolicy.compare("None"))
		m_secPolicy = SOPC_SecurityPolicy_None_URI;
	else if (!secPolicy.compare("Basic256"))
		m_secPolicy = SOPC_SecurityPolicy_Basic256_URI;
	else if (!secPolicy.compare("Basic256Sha256"))
		m_secPolicy = SOPC_SecurityPolicy_Basic256Sha256_URI;
	else
	{
		m_secPolicy = SOPC_SecurityPolicy_None_URI;
		Logger::getLogger()->error("Invalid Security policy '%s'", secPolicy.c_str());
	}
}

/**
 * Create an S2OPC OPCUA Toolkit trace file name if requested
 *
 * @param traceFile    If true, create an S2OPC OPCUA Toolkit trace file
 */
void
OPCUA::setTraceFile(const std::string& traceFile)
{
	if (traceFile == "True" || traceFile == "true" || traceFile == "TRUE")
	{
		string traceFilePath = getDataDir() + string("/logs/");
		size_t len = traceFilePath.length();
		m_traceFile = (char *) malloc(1 + len);
		strncpy(m_traceFile, traceFilePath.c_str(), len);
		m_traceFile[len] = '\0';
	}
	else
	{
		m_traceFile = NULL;
	}
}

/**
 * Clear down the subscriptions ahead of reconfiguration
 */
void
OPCUA::clearSubscription()
{
	lock_guard<mutex> guard(m_configMutex);
	m_subscriptions.clear();
}

/**
 * Add a subscription parent node to the list
 */
void
OPCUA::addSubscription(const string& parent)
{
	lock_guard<mutex> guard(m_configMutex);
	m_subscriptions.emplace_back(parent);
}

/**
 * Restart the OPCUA connection
 */
void
OPCUA::restart()
{
	stop();
	start();
}

/**
 * Add a set of subscriptions based on the content of m_subscripts. This
 * is a vector of node ID's
 */
int OPCUA::subscribe()
{
int res;
Logger *logger = Logger::getLogger();

	if (!m_connected)
	{
		logger->error("Attempt to subscribe aborted, no connection to the server");
		return 0;
	}

	if ((res = SOPC_ClientHelper_CreateSubscription(m_connectionId, datachange_callback)) != 0)
	{
		logger->error("Failed to create subscription %d", res);
		return 0;
	}
	vector<string> variables;
	for (auto it = m_subscriptions.cbegin(); it != m_subscriptions.cend(); it++)
	{
		Node node(m_connectionId, *it);
		if (node.getNodeClass() == OpcUa_NodeClass_Variable)
		{
			variables.push_back(*it);
		}
		else
		{
			browse(*it, variables);
		}
	}

	if (variables.size() == 0)
	{
		logger->error("No variables found to be monitored");
		return 0;
	}
	char **node_ids = (char **)malloc(variables.size() * sizeof(char *));
	if (!node_ids)
	{
		logger->error("Failed to allocate memory for %d subscriptions", variables.size());
		return 0;
	}
	int i = 0;
	for (auto it = variables.cbegin(); it != variables.cend(); it++)
	{
		try {
			Node *node = new Node(m_connectionId, variables[i].c_str());
			m_nodes.insert(pair<string, Node *>(variables[i], node));
			logger->debug("Subscribe to node %s, browseName %s", node->getNodeId().c_str(), node->getBrowseName().c_str());
			node_ids[i++] = strdup((char *)it->c_str());
		} catch (...) {
			logger->error("Unable to subscribe to node %s", it->c_str());
		}
	}
	res = SOPC_ClientHelper_AddMonitoredItems(m_connectionId, node_ids, variables.size(), NULL);
	switch (res)
	{
	case 0:
		logger->debug("Added %d monitored items", variables.size());
		break;
	case -1:
		logger->error("Failed to add monitored items, connection not valid");
		break;
	case -2:
		logger->error("Failed to add monitored items, invalid nodes for %d nodes", variables.size());
		break;
	case -100:
		logger->error("Failed to add monitored items");
		break;
	default:
		logger->error("Failed to add monitored items, nodeid '%s' not valid", node_ids[abs(res) - 3]);
		break;
	}
	for (i = 0; i < variables.size(); i++)
	{
		free(node_ids[i]);
	}
	free(node_ids);
	return res;
}




/**
 * Starts the plugin
 *
 * We register with the OPC UA server, retrieve all the objects under the parent
 * to which we are subscribing and start the process to enable OPC UA to send us
 * change notifications for those items.
 */
void
OPCUA::start()
{
int n_subscriptions = 0;
SOPC_ClientHelper_Security security;
Logger	*logger = Logger::getLogger();

	m_stopped = false;

	if (m_init == false)
	{
		SOPC_Log_Configuration logConfig = SOPC_Common_GetDefaultLogConfiguration();
		if (m_traceFile)
		{
			logConfig.logSysConfig.fileSystemLogConfig.logDirPath = m_traceFile;
			logConfig.logSystem = SOPC_LOG_SYSTEM_FILE;
			logConfig.logLevel = SOPC_LOG_LEVEL_DEBUG;
		}
		else
		{
			logConfig.logSysConfig.fileSystemLogConfig.logDirPath = NULL;
			logConfig.logSystem = SOPC_LOG_SYSTEM_NO_LOG;
		}

		SOPC_ReturnStatus initStatus = SOPC_CommonHelper_Initialize(&logConfig);
		if (initStatus != SOPC_STATUS_OK)
		{
			logger->fatal("Unable to initialise S2OPC CommonHelper library: %d", (int) initStatus);
			throw runtime_error("Unable to initialise CommonHelper library");
		}

		if (SOPC_ClientHelper_Initialize(disconnect_callback) != 0)
		{
			logger->fatal("Unable to initialise S2OPC ClientHelper library");
			throw runtime_error("Unable to initialise ClientHelper library");
		}
	}

	m_init = true;

	int res;
	SOPC_ClientHelper_GetEndpointsResult *endpoints = NULL;
	if ((res = SOPC_ClientHelper_GetEndpoints(m_url.c_str(), &endpoints)) == 0)
	{
		logger->info("Server has %d endpoints.\n", endpoints->nbOfEndpoints);

		for (int32_t i = 0; i < endpoints->nbOfEndpoints; i++)
		{
			logger->info("%d - url: %s\n", i, endpoints->endpoints[i].endpointUrl);
			logger->info("%d - security level: %d\n", i, endpoints->endpoints[i].securityLevel);
			logger->info("%d - security mode: %d\n", i, endpoints->endpoints[i].security_mode);
			logger->info("%d - security policy Uri: %s\n", i, endpoints->endpoints[i].security_policyUri);
			logger->info("%d - transport profile Uri: %s\n", i, endpoints->endpoints[i].transportProfileUri);

			SOPC_ClientHelper_UserIdentityToken* userIds = endpoints->endpoints[i].userIdentityTokens;
			for (int32_t j = 0; j < endpoints->endpoints[i].nbOfUserIdentityTokens; j++)
			{
				logger->info("%d %d - policy Id: %s\n", i, j, userIds[j].policyId);
				logger->info("%d %d - token type: %d\n", i, j, userIds[j].tokenType);
				logger->info("%d %d - issued token type: %s\n", i, j, userIds[j].issuedTokenType);
				logger->info("%d %d - issuer endpoint Url: %s\n", i, j, userIds[j].issuerEndpointUrl);
				logger->info("%d %d - security policy Uri: %s\n", i, j, userIds[j].securityPolicyUri);
			}
		}
	}
	else
	{
		logger->error("Unable to retrieve OPCUA endpoints: %d", res);
	}


	security.security_policy = m_secPolicy.c_str();
	security.security_mode = m_secMode;
	if (m_secMode == OpcUa_MessageSecurityMode_None)
	{
		security.security_policy = SOPC_SecurityPolicy_None_URI;
	}
	security.policyId = m_authPolicy.c_str();
	if (PolicyIdToUserTokenType(security.policyId) == OpcUa_UserTokenType_Anonymous)
	{
		logger->info("Using anonymous authentication policy");
		security.username = NULL;
		security.password = NULL;
	}
	else
	{
		security.username = m_username.c_str();
		security.password = m_password.c_str();
	}

	string certstore = "/usr/local/fledge/data";
	char *root = getenv("FLEDGE_ROOT");
	if (root)
	{
		certstore = root;
		certstore += "/data";
	}
	char *data = getenv("FLEDGE_DATA");
	if (data)
		certstore = data;
	certstore += "/etc/certs/";

	if (m_secMode == OpcUa_MessageSecurityMode_None)
	{
		security.path_cert_auth = NULL;
		security.path_crl = NULL;
		security.path_cert_srv = NULL;
		security.path_cert_cli = NULL;
		security.path_key_cli = NULL;
	}
	else
	{
		if (m_certAuth.length())
		{
			string cacert = certstore + m_certAuth + ".der";
			m_path_cert_auth = strdup(cacert.c_str());
			security.path_cert_auth = m_path_cert_auth;
			if (access(security.path_cert_auth, R_OK))
			{
				logger->error("Unable to access CA Certificate %s", security.path_cert_auth);
				SOPC_ClientHelper_Finalize();
				SOPC_CommonHelper_Clear();
				m_init = false;
				throw runtime_error("Unable to access CA Certificate");
			}
			logger->info("Using CA Cert %s", security.path_cert_auth);
		}
		else
		{
			security.path_cert_auth = NULL;
			logger->warn("No CA Cert has been configured");
		}
		if (m_caCrl.length())
		{
			string crl = certstore + m_caCrl + ".der";
			m_path_crl = strdup(crl.c_str());
			security.path_crl = m_path_crl;
			if (access(security.path_crl, R_OK))
			{
				logger->error("Unable to access CRL Certificate %s", security.path_crl);
				SOPC_ClientHelper_Finalize();
				SOPC_CommonHelper_Clear();
				m_init = false;
				throw runtime_error("Unable to access CRL Certificate");
			}
			logger->info("Using CRL Cert %s", security.path_crl);
		}
		else
		{
			security.path_crl = NULL;
			logger->warn("No Certificate Revocation List has been configured");
		}
		if (m_serverPublic.length())
		{
			string certSrv = certstore + m_serverPublic + ".der";
			m_path_cert_srv = strdup(certSrv.c_str());
			security.path_cert_srv = m_path_cert_srv;
			if (access(security.path_cert_srv, R_OK))
			{
				logger->error("Unable to access Server Certificate %s", security.path_cert_srv);
				SOPC_ClientHelper_Finalize();
				SOPC_CommonHelper_Clear();
				m_init = false;
				throw runtime_error("Unable to access Server Certificate");
			}
			logger->info("Using Srv Cert %s", security.path_cert_srv);
		}
		else
		{
			security.path_cert_srv = NULL;
			logger->warn("No Server Certificate has been configured");
		}
		if (m_clientPublic.length())
		{
			string certClient = certstore + m_clientPublic + ".der";
			m_path_cert_cli = strdup(certClient.c_str());
			security.path_cert_cli = m_path_cert_cli;
			if (access(security.path_cert_cli, R_OK))
			{
				logger->error("Unable to access Client Certificate %s", security.path_cert_cli);
				SOPC_ClientHelper_Finalize();
				SOPC_CommonHelper_Clear();
				m_init = false;
				throw runtime_error("Unable to access Client Certificates");
			}
			logger->info("Using Client Cert %s", security.path_cert_cli);
		}
		else
		{
			security.path_cert_cli = NULL;
			logger->warn("No Client Certificate has been configured");
		}
		if (m_clientPrivate.length())
		{
			string keyClient = certstore + "pem/" + m_clientPrivate + ".pem";
			m_path_key_cli = strdup(keyClient.c_str());
			security.path_key_cli = m_path_key_cli;
			if (access(security.path_key_cli, R_OK) != F_OK)
			{
				// If not in pem subdirectory try without subdirectory
				string altKeyClient = certstore + m_clientPrivate + ".pem";
				free(m_path_key_cli);
				m_path_key_cli = strdup(altKeyClient.c_str());
				security.path_key_cli = m_path_key_cli;
				if (access(security.path_key_cli, R_OK) != F_OK)
				{
					logger->error("Unable to access Client key %s", security.path_key_cli);
					SOPC_ClientHelper_Finalize();
					SOPC_CommonHelper_Clear();
					m_init = false;
					throw runtime_error("Unable to access Client key");
				}
			}
			logger->info("Using Client key %s", security.path_key_cli);
		}
		else
		{
			security.path_key_cli = NULL;
			logger->warn("No Client Key has been configured");
		}
	}

	// Check for a matching endpoint
	if (endpoints && endpoints->endpoints)
	{
		logger->debug("Endpoint matching starting....");
		bool matched = false;
		bool matchedMode = false;
		bool matchedPolicyURL = false;
		bool matchedPolicyId = false;
		for (int32_t i = 0; i < endpoints->nbOfEndpoints && matched == false; i++)
		{
			if (endpoints->endpoints[i].security_mode != m_secMode)
			{
				logger->debug("%d: security mode does not match %s", i, securityMode(m_secMode).c_str());
				continue;
			}
			else
			{
				logger->debug("Endpoint %d matches on security mode %s", i, securityMode(m_secMode).c_str());
				matchedMode = true;
			}
			if (endpoints->endpoints[i].security_policyUri &&
					strcmp(endpoints->endpoints[i].security_policyUri, security.security_policy))
			{
				logger->debug("%d: security policy mismatch %s != %s", i, endpoints->endpoints[i].security_policyUri, security.security_policy);
				continue;
			}
			else
			{
				logger->debug("Endpoint %d matches on security policy %s", i, security.security_policy);
				matchedPolicyURL = true;
			}
			logger->debug("%d: checking user ID tokens", i);
			if (matchedMode && matchedPolicyURL)
			{
				SOPC_ClientHelper_UserIdentityToken* userIds = endpoints->endpoints[i].userIdentityTokens;
				for (int32_t j = 0; matched == false && j < endpoints->endpoints[i].nbOfUserIdentityTokens; j++)
				{
					OpcUa_UserTokenType tokenType = PolicyIdToUserTokenType(security.policyId);

					if (userIds[j].tokenType == tokenType &&
						userIds[j].securityPolicyUri &&
						!strcmp(userIds[j].securityPolicyUri, security.security_policy))
					{
						matchedPolicyId = true;
					}
					else if (userIds[j].tokenType == tokenType && tokenType == OpcUa_UserTokenType_Anonymous)
					{
						matchedPolicyId = true;
					}
					else
					{
						matchedPolicyId = false;
					}

					if (matchedPolicyId)
					{
						security.policyId = userIds[j].policyId; // Policy Id must match the OPC UA server's name for it
						logger->debug("Endpoint %d matches on policyId %s (%d)", i, security.policyId, (int) userIds[j].tokenType);
						matched = true;
					}
					else
					{
						logger->debug("%d: '%s' != '%s' (%d)", i, security.policyId, userIds[j].policyId, (int) userIds[j].tokenType);
						continue;
					}
				}
			}
		}
		if (!matched)
		{
			logger->fatal("Failed to match any server endpoints with Security Mode '%s', Security Policy '%s', Authentication policy '%s'",
				securityMode(m_secMode).c_str(), security.security_policy, m_authPolicy.c_str());
			if (!matchedMode)
				logger->error("There are no endpoints that match the security mode requested");
			if (!matchedPolicyURL)
				logger->error("There are no endpoints that match the Policy URL %s",
						security.security_policy);
			if (!matchedPolicyId)
				logger->error("There are no endpoints that match the Policy Id %s",
						security.policyId);
            SOPC_ClientHelper_Finalize();
			SOPC_CommonHelper_Clear();
			m_init = false;
			throw runtime_error("Failed to find matching endpoint in OPC/UA server");
		}
		else
		{
			logger->info("Matched Endpoint: Security Mode '%s', Security Policy '%s', Authentication policy '%s'",
				securityMode(security.security_mode).c_str(), security.security_policy, security.policyId);
		}
	}

	m_configurationId = SOPC_ClientHelper_CreateConfiguration(m_url.c_str(), &security, NULL);
	if (m_configurationId <= 0)
	{
		logger->fatal("Failed to create configuration for endpoint '%s' %d", m_url.c_str(), m_configurationId);
		switch (m_configurationId)
		{
			case 0:
				logger->fatal("Invalid endpointURL %s", m_url.c_str());
				break;
			case -1:
				logger->fatal("Invalid security detected");
				break;
			case -11:
				logger->fatal("Invalid security policy %s", security.security_policy);
				break;
			case -12:
				logger->fatal("Invalid security mode %d", security.security_mode);
				break;
			case -13:
				logger->fatal("Invalid CA Cert %s", security.path_cert_auth);
				break;
			case -14:
				logger->fatal("Invalid CRL Cert %s", security.path_crl);
				break;
			case -15:
				logger->fatal("Invalid Server Cert %s", security.path_cert_srv);
				break;
			case -16:
				logger->fatal("Invalid Client Cert %s", security.path_cert_cli);
				break;
			case -17:
				logger->fatal("Invalid Client key %s", security.path_key_cli);
				break;
			case -18:
				logger->fatal("Invalid policy id %s", security.policyId);
				break;
			case -19:
				logger->fatal("Invalid username %s", security.username);
				break;
			case -20:
				logger->fatal("Invalid password %s", security.password);
				break;
		}
		throw runtime_error("Failed to create successful S2OPCUA configuration");;
	}

	m_connectionId = SOPC_ClientHelper_CreateConnection(m_configurationId);
	if (m_connectionId == -1)
	{
		logger->fatal("Failed to create OPC/UA connection to server %s, invalid configuration detected", m_url.c_str());
		SOPC_ClientHelper_Finalize();
		SOPC_CommonHelper_Clear();
		m_init = false;
		throw runtime_error("Failed to create OPC/UA connection to server, invalid configuration detected");
	}
	if (m_connectionId == -100)
	{
		logger->fatal("Failed to create OPC/UA connection to server %s, connection failed", m_url.c_str());
		SOPC_ClientHelper_Finalize();
		SOPC_CommonHelper_Clear();
		m_init = false;
		throw runtime_error("Failed to create OPC/UA connection to server, connection failed");
	}

	m_connected = true;
	logger->info("Successfully connected to OPC/UA Server: %s", m_url.c_str());

	if (endpoints)
	{
		if (endpoints->endpoints)
		{
			for (int32_t i = 0; i < endpoints->nbOfEndpoints; i++)
			{
				free(endpoints->endpoints[i].endpointUrl);
				free(endpoints->endpoints[i].security_policyUri);
				free(endpoints->endpoints[i].transportProfileUri);
				if (NULL != endpoints->endpoints[i].userIdentityTokens)
				{
					for (int32_t j = 0; j < endpoints->endpoints[i].nbOfUserIdentityTokens; j++)
					{
						free(endpoints->endpoints[i].userIdentityTokens[j].policyId);
						free(endpoints->endpoints[i].userIdentityTokens[j].issuedTokenType);
						free(endpoints->endpoints[i].userIdentityTokens[j].issuerEndpointUrl);
						free(endpoints->endpoints[i].userIdentityTokens[j].securityPolicyUri);
					}
				free(endpoints->endpoints[i].userIdentityTokens);
				}
			}
		    free(endpoints->endpoints);
		}
		free(endpoints);
	}

	subscribe();
}


/**
 * Stop all subscriptions and disconnect from the OPCUA server
 */
void
OPCUA::stop()
{
	m_stopped = true;
	if (m_connected)
	{
		m_connected = false;
		SOPC_ClientHelper_Unsubscribe(m_connectionId);
		SOPC_ClientHelper_Disconnect(m_connectionId);
	}
	SOPC_ClientHelper_Finalize();
	SOPC_CommonHelper_Clear();
	m_init = false;
	// TODO Cleanup memory
	if (m_path_cert_auth)
	{
		free(m_path_cert_auth);
		m_path_cert_auth = NULL;
	}
	if (m_path_cert_auth)
	{
		free(m_path_cert_auth);
		m_path_cert_auth = NULL;
	}
	if (m_path_crl)
	{
		free(m_path_crl);
		m_path_crl = NULL;
	}
	if (m_path_cert_srv)
	{
		free(m_path_cert_srv);
		m_path_cert_srv = NULL;
	}
	if (m_path_cert_cli)
	{
		free(m_path_cert_cli);
		m_path_cert_cli = NULL;
	}
	if (m_path_key_cli)
	{
		free(m_path_key_cli);
		m_path_key_cli = NULL;
	}
	if (m_traceFile)
	{
		free(m_traceFile);
		m_traceFile = NULL;
	}
}

/**
 * Called when a data changed event is received. This calls back to the south service
 * and adds the points to the readings queue to send.
 *
 * @param points    The points in the reading we must create
 */
void OPCUA::ingest(vector<Datapoint *> points, long user_ts)
{
string asset = m_asset + points[0]->getName();

    Reading rdng(asset, points);
    // rdng.setUserTimestamp(user_ts);
    (*m_ingest)(m_data, rdng);
}

/**
 * Construct a node class for the given nodeID
 *
 * @param conn		The connection to the OPCUA server
 * @param nodeId	The ID of the node to read
 */
OPCUA::Node::Node(uint32_t conn, const string& nodeId) : m_nodeID(nodeId)
{
SOPC_ClientHelper_ReadValue readValue[3];
SOPC_DataValue values[3];

	readValue[0].nodeId = (char *)nodeId.c_str();
	readValue[0].attributeId = SOPC_AttributeId_BrowseName;
	readValue[0].indexRange = NULL;
	readValue[1].nodeId = (char *)nodeId.c_str();
	readValue[1].attributeId = SOPC_AttributeId_DataType;
	readValue[1].indexRange = NULL;
	readValue[2].nodeId = (char *)nodeId.c_str();
	readValue[2].attributeId = SOPC_AttributeId_NodeClass;
	readValue[2].indexRange = NULL;

	int res;
	if ((res = SOPC_ClientHelper_Read(conn, readValue, 3, values)) == 0)
	{
		SOPC_Variant variant = values[0].Value;
		if (variant.Value.Qname)
			m_browseName = (char *)variant.Value.Qname->Name.Data;
		SOPC_Variant classVariant = values[2].Value;
		m_nodeClass = (OpcUa_NodeClass)classVariant.Value.Int32;
	}
	else
	{
		Logger::getLogger()->error("Failed to read node \"%s\", %d", nodeId.c_str(), res);
		throw runtime_error("Failed to read node");
	}
}

/**
 * Browse a node and add to the subscription list if it is a variable.
 * If it is a FolderType then recurse down the child nodes
 *
 * @param nodeid	Nodeid of the candidiate to subscribe to
 * @param variables	Vector of variable node ID's
 */
void OPCUA::browse(const string& nodeid, vector<string>& variables)
{
	int res;

        SOPC_ClientHelper_BrowseRequest browseRequest;
        SOPC_ClientHelper_BrowseResult browseResult;

        browseRequest.nodeId = (char *)nodeid.c_str();           // Root/Objects/
        browseRequest.direction = OpcUa_BrowseDirection_Forward; // forward
        browseRequest.referenceTypeId = "";                      // all reference types
        browseRequest.includeSubtypes = true;

	Logger::getLogger()->debug("Browse '%s'", browseRequest.nodeId);
        /* Browse specified node */
        res = SOPC_ClientHelper_Browse(m_connectionId, &browseRequest, 1, &browseResult);

	if (res != 0)
	{
		Logger::getLogger()->info("Browse returned %d for node %s", res, nodeid.c_str());
		return;
	}
	Logger::getLogger()->debug("status: %d, nbOfResults: %d", browseResult.statusCode, browseResult.nbOfReferences);

	if (browseResult.nbOfReferences == 0)
	{
		Logger::getLogger()->error("Unable to locate the OPCUA node '%s'", nodeid.c_str());
	}

        for (int32_t i = 0; i < browseResult.nbOfReferences; i++)
        {
		if (browseResult.references[i].nodeClass == OpcUa_NodeClass_Object)
		{
			browse(browseResult.references[i].nodeId, variables);
		}
		if (browseResult.references[i].nodeClass == OpcUa_NodeClass_Variable)
		{
			variables.push_back(browseResult.references[i].nodeId);
		}
		Logger::getLogger()->debug("Item #%d: NodeId %s, displayName %s, nodeClass %s",
			       	i, browseResult.references[i].nodeId,
				browseResult.references[i].displayName,
				nodeClass(browseResult.references[i].nodeClass).c_str());

		free(browseResult.references[i].nodeId);
		free(browseResult.references[i].displayName);
		free(browseResult.references[i].browseName);
		free(browseResult.references[i].referenceTypeId);
        }
        free(browseResult.references);
}

/**
 * Disconnection callback has been called
 */
void OPCUA::disconnect()
{
	Logger::getLogger()->info("OPCUA disconnection");
	m_connected = false;
	if (m_stopped == false)
	{
		// This was not a user initiated stop
		if (m_background && m_background->joinable())	// Collect the background thread
		{
			m_background->join();
			m_background = NULL;
		}
		if (m_background == NULL)
		{
			m_background = new thread(retryThread, this);
		}

	}
}

/**
 * Run a background thread to rety the connection after a forced disconnect.
 *
 * There will be a delay between retires starting at 100ms and backing off to
 * once a minute.
 */
void OPCUA::retry()
{
	int delay = 100;
	while (!m_connected)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(delay));
		try {
			start();
		} catch (...) {
			// ignore
		}
		if (delay < 60 * 1000)
			delay *= 2;
	}
}

/**
 * Return an OPCUA security mode as a string
 */
string OPCUA::securityMode(OpcUa_MessageSecurityMode mode)
{
	switch (mode)
	{
	case OpcUa_MessageSecurityMode_None:
		return string("None");
	case OpcUa_MessageSecurityMode_Sign:
		return string("Sign");
	case OpcUa_MessageSecurityMode_SignAndEncrypt:
		return string("Sign & Encrypt");
	default:
		return string("invalid");
	}

}

/**
 * Return a string representation of a NodeClass
 */
string OPCUA::nodeClass(OpcUa_NodeClass nodeClass)
{
	switch (nodeClass)
	{
		case OpcUa_NodeClass_Unspecified:
			return string("Unspecified");
		case OpcUa_NodeClass_Object:
			return string("Object");
		case OpcUa_NodeClass_Variable:
			return string("Variable");
		case OpcUa_NodeClass_Method:
			return string("Method");
		case OpcUa_NodeClass_ObjectType:
			return string("ObjectType");
		case OpcUa_NodeClass_VariableType:
			return string("VariableType");
		case OpcUa_NodeClass_DataType:
			return string("DataType");
		case OpcUa_NodeClass_View:
			return string("View");
		case OpcUa_NodeClass_SizeOf:
			return string("SizeOf");
	}
	return string("Unknow");
}

