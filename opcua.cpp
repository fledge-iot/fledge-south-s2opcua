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


// OPC-UA time (hundreds of nanosecs since 1601/01/01 00:00:00 UTC)
// NTP time (hundreds of nanosecs since 1900/01/01 00:00:00 UTC)
// Unix time (seconds since 1970/01/01 00:00:00 UTC)

#if 0 // TODO
unsigned long Opcua_Time_2_Unix_Time(uint64_t uts)
{
    /* First, subtract the difference between epochs */
s_OPCTimeToNTP(pVal->SourceTimesta
mp);
        plsVal->server_timestamp = Helpers_OPCTimeToNTP(pVal->ServerTime
stamp);
        /* Value is ready, modify given pointer *
/
        *pplsVal = plsVal;
    }

    /* Partial mallocs */
 
   if (SOPC_STATUS_OK != status)
    {
        if (NULL != plsVal)
        {
            SOPC_Free(plsVa
    uint64_t seconds = ((uts / 10000000) << 32);
}
#endif

/**
 * Callback function for a disconnection deom the OPCUA server
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
 * that we have registered to receives changes.
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
 * A data value we are monitoring has changed
 *
 * @param nodeId	The ID of the node that has changed
 * @param value		The new vlaue of the node
 */
void OPCUA::dataChange(const char *nodeId, const SOPC_DataValue *value)
{
DatapointValue* dpv = NULL;

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
				m_disableCertVerif(false)
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
		browse(*it, variables);
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
	res = SOPC_ClientHelper_AddMonitoredItems(m_connectionId, node_ids, variables.size());
	if (res != 0)
	{
		logger->error("Failed to add monitored items, %d", res);
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


	SOPC_ClientHelper_Initialize("/tmp/s2opc_wrapper_subscribe_logs/", SOPC_LOG_LEVEL_DEBUG, disconnect_callback);

	int res;
	SOPC_ClientHelper_GetEndpointsResult *endpoints;
	if ((res = SOPC_ClientHelper_GetEndpoints(m_url.c_str(), &endpoints)) == 0)
	{
		logger->info("Server has %d endpoints.\n", endpoints->nbOfEndpoints);

		for (int32_t i = 0; i < endpoints->nbOfEndpoints; i++)
		{
			logger->info("%d - url: %s\n", i, endpoints->endpoints[i].endpointUrl);
			logger->info("  - security level: %d\n", endpoints->endpoints[i].securityLevel);
			logger->info("  - security mode: %d\n", endpoints->endpoints[i].security_mode);
			logger->info("  - security policy Uri: %s\n", endpoints->endpoints[i].security_policyUri);
			logger->info("  - transport profile Uri: %s\n", endpoints->endpoints[i].transportProfileUri);

			SOPC_ClientHelper_UserIdentityToken* userIds = endpoints->endpoints[i].userIdentityTokens;
			for (int32_t j = 0; j < endpoints->endpoints[i].nbOfUserIdentityTokens; j++)
			{
				logger->info("%3d - policy Id: %s\n", j, userIds[j].policyId);
				logger->info("    - token type: %d\n", userIds[j].tokenType);
				logger->info("    - issued token type: %s\n", userIds[j].issuedTokenType);
				logger->info("    - issuer endpoint Url: %s\n", userIds[j].issuerEndpointUrl);
				logger->info("    - security policy Uri: %s\n", userIds[j].securityPolicyUri);
			}
		}
	}
	else
	{
		logger->error("Unable to retrieve OPCUA endpoints: %d", res);
	}
	security.security_policy = m_secPolicy.c_str();
	security.security_mode = m_secMode;
	security.policyId = m_authPolicy.c_str();
	if (!strcmp(security.policyId, "anonymous"))
	{
		security.username = NULL;
		security.password = NULL;
	}
	else
	{
		security.username = m_username.c_str();
		security.password = m_password.c_str();
	}


	// Check for a matching endpoint
	if (endpoints && endpoints->endpoints)
	{
		bool matched = false;
		bool matchedMode = false;
		bool matchedPolicyURL = false;
		bool matchedPolicyId = false;
		for (int32_t i = 0; i < endpoints->nbOfEndpoints; i++)
		{
			if (endpoints->endpoints[i].security_mode != m_secMode)
			{
				continue;
			}
			else
			{
				matchedMode = true;
			}
			if (endpoints->endpoints[i].security_policyUri &&
					strcmp(endpoints->endpoints[i].security_policyUri, security.security_policy))
			{
				continue;
			}
			else
			{
				matchedPolicyURL = true;
			}
			SOPC_ClientHelper_UserIdentityToken* userIds = endpoints->endpoints[i].userIdentityTokens;
			for (int32_t j = 0; j < endpoints->endpoints[i].nbOfUserIdentityTokens; j++)
			{
				if (userIds[j].policyId && strcmp(security.policyId, userIds[j].policyId))
					continue;
				else
					matchedPolicyId = true;
				matched = true;
			}
		}
		if (!matched)
		{
			logger->fatal("Failed to match any server endpoints");
			if (!matchedMode)
				logger->error("There are no endpoints that match the security mode requested");
			if (!matchedPolicyURL)
				logger->error("There are no endpoints that match the Policy URL %s",
						security.security_policy);
			if (!matchedPolicyId)
				logger->error("There are no endpoints that match the Policy Id %s",
						security.policyId);
			throw runtime_error("Failed to find matching endpoint in OPC/UA server");
		}
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
	if (m_certAuth.length())
	{
		string cacert = certstore + m_certAuth + ".der";
		security.path_cert_auth = cacert.c_str();
		if (access(security.path_cert_auth, R_OK))
		{
			logger->error("Unable to access CA Certificate %s", security.path_cert_auth);
			return;
		}
		logger->info("Using CA Cert %s", security.path_cert_auth);
	}
	if (m_caCrl.length())
	{
		string crl = certstore + m_caCrl + ".der";
		security.path_crl = crl.c_str();
		if (access(security.path_crl, R_OK))
		{
			logger->error("Unable to access CRL Certificate %s", security.path_crl);
			return;
		}
		logger->info("Using CRL Cert %s", security.path_crl);
	}
	if (m_serverPublic.length())
	{
		string certSrv = certstore + m_serverPublic + ".der";
		security.path_cert_srv = certSrv.c_str();
		if (access(security.path_cert_srv, R_OK))
		{
			logger->error("Unable to access Server Certificate %s", security.path_cert_srv);
			return;
		}
		logger->info("Using Srv Cert %s", security.path_cert_srv);
	}
	if (m_clientPublic.length())
	{
		string certClient = certstore + m_clientPublic + ".der";
		security.path_cert_cli = certClient.c_str();
		if (access(security.path_cert_cli, R_OK))
		{
			logger->error("Unable to access Client Certificate %s", security.path_cert_cli);
			return;
		}
		logger->info("Using Client Cert %s", security.path_cert_cli);
	}
	if (m_clientPrivate.length())
	{
		string keyClient = certstore + m_clientPrivate + ".pem";
		security.path_key_cli = keyClient.c_str();
		if (access(security.path_key_cli, R_OK))
		{
			logger->error("Unable to access Client key %s", security.path_key_cli);
			return;
		}
		logger->info("Using Client key %s", security.path_cert_cli);
	}

	m_configurationId = SOPC_ClientHelper_CreateConfiguration(m_url.c_str(), &security);
	if (m_configurationId <= 0)
	{
		logger->fatal("Failed to create configuration %d", m_configurationId);
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
		return;
	}

	m_connectionId = SOPC_ClientHelper_CreateConnection(m_configurationId);
	if (m_configurationId <= 0)
	{
		logger->fatal("Failed to create OPC/UA connection to server %s", m_url.c_str());
		return;
	}

	m_connected = true;
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
	if (m_connected)
	{
		m_connected = false;
		SOPC_ClientHelper_Unsubscribe(m_connectionId);
		SOPC_ClientHelper_Disconnect(m_connectionId);
	}
	// TODO Cleanup memory
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
		m_browseName = (char *)variant.Value.Qname->Name.Data;
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

        browseRequest.nodeId = (char *)nodeid.c_str();                      // Root/Objects/
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

	bool subscribeChild = false;
	if (browseResult.nbOfReferences == 1 
			&& strcmp(browseResult.references[0].displayName, "BaseDataVariableType") == 0)
	{
		variables.push_back(nodeid);
	}
	else if (strcmp(browseResult.references[0].displayName, "FolderType") == 0)
	{
		subscribeChild = true;
	}
        for (int32_t i = 0; i < browseResult.nbOfReferences; i++)
        {
		Logger::getLogger()->debug("Item #%d: NodeId %s, displayName %s",
			       	i, browseResult.references[i].nodeId,
				browseResult.references[i].displayName);
		if (i > 0 && subscribeChild)
		{
			browse(browseResult.references[i].nodeId, variables);
		}

		free(browseResult.references[i].nodeId);
		free(browseResult.references[i].displayName);
		free(browseResult.references[i].browseName);
		free(browseResult.references[i].referenceTypeId);
        }
        free(browseResult.references);
}

/**
 * Discinnection callback has been called
 */
void OPCUA::disconnect()
{
	Logger::getLogger()->info("OPCUA disconnection");
	m_connected = false;
}
