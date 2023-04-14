/*
 * Fledge S2OPCUA South service plugin
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
#include <chrono>
#include <math.h>

using namespace std;

// Hold subscription variables
map<string, bool> subscriptionVariables;

static OPCUA *opcua = NULL;

/**
 * Callback function for a disconnection from the OPCUA server
 *
 * @param connectionId	The connection ID
 */
static void disconnect_callback(const uint32_t connectionId)
{
	if (opcua)
	{
		opcua->disconnect(connectionId);
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
		char anonymous[] = "anonymous";
		char username[] = "username";

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
 * Convert SOPC_DateTime to a string in ISO8601 format with subseconds and UTC time zone
 *
 * @param timestamp	SOPC_DateTime to convert
 */
static std::string DateTimeToString(SOPC_DateTime timestamp)
{
	const int64_t daysBetween1601And1970 = 134774;
	const int64_t secsFrom1601To1970 = daysBetween1601And1970 * 24 * 3600LL;

	// Convert timestamp to time_t and subseconds
	int64_t raw = static_cast<int64_t>(timestamp);
	uint64_t micro = raw % 10000000;
	raw -= micro;
	raw = raw / 10000000LL;
	struct timeval tm;
	tm.tv_sec = (time_t)(raw - secsFrom1601To1970);
	tm.tv_usec = (suseconds_t)(micro / 10);

	// Populate tm structure with UTC time
	struct tm timeinfo;
	gmtime_r(&tm.tv_sec, &timeinfo);

	// Build date_time with format YYYY-MM-DD HH24:MM:SS.MS+00:00
	// Create datetime with seconds
	char date_time[40], usec[15];
	std::strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

	// Add microseconds and the UTC time zone offset of zero
	snprintf(usec, sizeof(usec), ".%06lu+00:00", tm.tv_usec);
	strcat(date_time, usec);
	return std::string(date_time);
}

/**
 * Free memory from an SOPC Endpoints collection
 *
 * @param endpoints	An SOPC Endpoints collection
 */
static void FreeEndpointCollection(SOPC_ClientHelper_GetEndpointsResult *endpoints)
{
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
}

/**
 * A data value we are monitoring has changed
 *
 * @param nodeId	The ID of the node that has changed
 * @param value		The new value of the node
 */
void OPCUA::dataChange(const char *nodeId, const SOPC_DataValue *value)
{
	DatapointValue *dpv = NULL;

	setRetryThread(false);
	Logger::getLogger()->debug("Data change call for Node %s", nodeId);

	// Enforce minimum reporting interval in software
	struct timeval now;
	gettimeofday(&now, NULL);
	auto it = m_lastIngest.find(nodeId);
	if (it != m_lastIngest.end())
	{
		struct timeval lastIngest = it->second;
		struct timeval diff;
		timersub(&now, &lastIngest, &diff);
		long ms = diff.tv_sec * 1000 + (diff.tv_usec / 1000);
		if (ms < m_reportingInterval)
		{
			Logger::getLogger()->debug("Ingest of %s too soon after last ingest, as defined by minimum reporting interval", nodeId);
			return;
		}
	}
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
			case SOPC_DateTime_Id:
				dpv = new DatapointValue(DateTimeToString(variant.Value.Date));
				break;
			case SOPC_ByteString_Id:
				Logger::getLogger()->warn("Node %s: Unable to handle ByteStrings currently", nodeId);
				break;
			case SOPC_Null_Id:
				Logger::getLogger()->warn("Node %s: Unable to handle items with Null type", nodeId);
				break;
			default:
				Logger::getLogger()->warn("Node %s: Unable to determine type %d", nodeId, (int)variant.BuiltInTypeId);
				break;
			}
		}
		else if (variant.ArrayType == SOPC_VariantArrayType_Array)
		{
			// TODO Support Array types
			Logger::getLogger()->error("Node %s: Array type not supported", nodeId);
		}
		else if (variant.ArrayType == SOPC_VariantArrayType_Matrix)
		{
			Logger::getLogger()->error("Node %s: Matrix type not supported", nodeId);
		}
		else
		{
			Logger::getLogger()->error("Node %s: Unable to determine array type", nodeId);
		}

		if (dpv)
		{
			vector<Datapoint *> points;
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

			SOPC_DateTime srcTimestamp = value->SourceTimestamp;
			time_t seconds;
			struct timeval tm_userts;
			if (SOPC_Time_ToTimeT(srcTimestamp, &seconds) == SOPC_STATUS_OK)
			{
				double TimeAsSecondsFloat = ((double)srcTimestamp) / 1.0E7; // divide by 100 nanoseconds
				double integerPart = 0.0;
				tm_userts.tv_sec = seconds;
				tm_userts.tv_usec = (suseconds_t)(1E6 * modf(TimeAsSecondsFloat, &integerPart));
			}

			string parent = "noParent";
			auto p = m_parentNodes.find(nodeId);
			if (p != m_parentNodes.end())
			{
				parent = p->second->getBrowseName();
			}

			if (m_includePathAsMetadata)
			{
				try
				{
					dpv = new DatapointValue(m_fullPaths.at(nodeId));
					points.push_back(new Datapoint(m_metaDataName, *dpv));
				}
				catch (...)
				{
					Logger::getLogger()->warn("Node %s: Full Path not found", nodeId);
				}
			}

			ingest(points, tm_userts, parent);
		}
	}

	if (it != m_lastIngest.end())
	{
		it->second = now;
	}
	else
	{
		m_lastIngest[nodeId] = now;
	}
}

/**
 * Constructor for the opcua plugin
 */
OPCUA::OPCUA() : m_publishPeriod(1000),
				 m_maxKeepalive(30), m_tokenTarget(1),
				 m_configurationId(0),
				 m_connectionId(0),
				 m_disableCertVerif(false),
				 m_path_cert_auth(NULL),
				 m_path_crl(NULL),
				 m_path_cert_srv(NULL),
				 m_path_cert_cli(NULL),
				 m_path_key_cli(NULL),
				 m_background(NULL),
				 m_init(false),
				 m_traceFile(NULL),
				 m_assetNaming(ASSET_NAME_SINGLE)
{
	m_connected.store(false);
	m_stopped.store(false);
	opcua = this;
}

/**
 * Destructor for the opcua interface
 */
OPCUA::~OPCUA()
{
	m_stopped.store(true);
	setRetryThread(false);
	Logger::getLogger()->debug("OPCUA::~OPCUA: retry thread stopped");
}

/**
 * Clear OPCUA object members and reset default values
 */
void OPCUA::clear()
{
	m_url.clear();
	m_asset.clear();
	m_secPolicy.clear();
	m_authPolicy.clear();
	m_username.clear();
	m_password.clear();
	m_certAuth.clear();
	m_serverPublic.clear();
	m_clientPublic.clear();
	m_clientPrivate.clear();
	m_caCrl.clear();
	m_subscriptions.clear();
	m_fullPaths.clear();
	m_metaDataName.clear();
	m_assetNaming = ASSET_NAME_SINGLE;
	m_reportingInterval = 100;
	m_secMode = OpcUa_MessageSecurityMode_Invalid;
	if (m_traceFile)
	{
		free(m_traceFile);
		m_traceFile = NULL;
	}
}

/**
 * Parse plugin configuration
 *
 * @param config	configuration information
 */
void OPCUA::parseConfig(ConfigCategory &config)
{
	clear();

	if (config.itemExists("url"))
	{
		string url = config.getValue("url");
		newURL(url);
	}
	else
	{
		Logger::getLogger()->error("OPC UA plugin is missing a URL");
	}

	if (config.itemExists("asset"))
	{
		setAssetName(config.getValue("asset"));
	}

	if (config.itemExists("assetNaming"))
	{
		setAssetNaming(config.getValue("assetNaming"));
	}

	if (config.itemExists("reportingInterval"))
	{
		long val = strtol(config.getValue("reportingInterval").c_str(), NULL, 10);
		setReportingInterval(val);
	}
	else
	{
		setReportingInterval(100);
	}

	if (config.itemExists("subscription"))
	{
		// Now add the subscription data
		string map = config.getValue("subscription");
		rapidjson::Document doc;
		doc.Parse(map.c_str());
		if (!doc.HasParseError())
		{
			clearSubscription();
			if (doc.HasMember("subscriptions") && doc["subscriptions"].IsArray())
			{
				const rapidjson::Value &subs = doc["subscriptions"];
				for (rapidjson::SizeType i = 0; i < subs.Size(); i++)
				{
					Logger::getLogger()->info("Adding subscription for NodeId %d = '%s'", i, subs[i].GetString());
					addSubscription(subs[i].GetString());
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
		setSecMode(config.getValue("securityMode"));
	}

	std::string secPolicy;
	if (config.itemExists("securityPolicy"))
	{
		secPolicy = config.getValue("securityPolicy");
		if (secPolicy.compare("None") == 0 || secPolicy.compare("Basic256") == 0 || secPolicy.compare("Basic256Sha256") == 0)
			setSecPolicy(secPolicy);
		else
			throw exception();
	}

	if (config.itemExists("userAuthPolicy"))
	{
		std::string authPolicy = config.getValue("userAuthPolicy");
		setAuthPolicy(authPolicy);
	}

	if (config.itemExists("username"))
	{
		setUsername(config.getValue("username"));
	}

	if (config.itemExists("password"))
	{
		setPassword(config.getValue("password"));
	}

	if (config.itemExists("caCert"))
	{
		setCaCert(config.getValue("caCert"));
	}

	if (config.itemExists("serverCert"))
	{
		setServerCert(config.getValue("serverCert"));
	}

	if (config.itemExists("clientCert"))
	{
		setClientCert(config.getValue("clientCert"));
	}

	if (config.itemExists("clientKey"))
	{
		setClientKey(config.getValue("clientKey"));
	}

	if (config.itemExists("caCrl"))
	{
		setRevocationList(config.getValue("caCrl"));
	}

	m_includePathAsMetadata = false;
	if (config.itemExists("parentPathMetadata"))
	{
		if (config.getValue("parentPathMetadata") == "true")
		{
			m_includePathAsMetadata = true;
		}
	}

	if (config.itemExists("parentPath"))
	{
		m_metaDataName = config.getValue("parentPath");
		if (m_metaDataName.size() == 0)
		{
			m_metaDataName.append("OPCUAPath");
		}
	}

	if (config.itemExists("traceFile"))
	{
		setTraceFile(config.getValue("traceFile"));
	}
}

/**
 * Restart the plugin with an updated configuration
 *
 * @param config	updated configuration information
 */
void OPCUA::reconfigure(ConfigCategory &config)
{
	// Setting m_stopped to 'true' will cause the retry thread to shut down.
	// Do not lock the mutex here; it would prevent the retry thread from completing.
	m_stopped.store(true);
	setRetryThread(false);

	lock_guard<mutex> guard(m_configMutex);

	opcua->stop();
	opcua->parseConfig(config);
	Logger::getLogger()->info("OPC UA plugin reconfiguration in progress...");
	opcua->start();
	if (m_connected.load())
	{
		Logger::getLogger()->info("OPC UA plugin restarted after reconfiguration");
	}
	else
	{
		Logger::getLogger()->error("OPC UA plugin not connected after reconfiguration");
	}
}

/**
 * Set the asset name for the asset we write
 *
 * @param asset Set the name of the asset with insert into readings
 */
void OPCUA::setAssetName(const std::string &asset)
{
	m_asset = asset;
}

/**
 * Set the minimum interval between data change events for subscriptions
 *
 * @param value    Interval in milliseconds
 */
void OPCUA::setReportingInterval(long value)
{
	m_reportingInterval = value;
}

/**
 * Set the message security mode
 *
 * @param value    Security mode string
 */
void OPCUA::setSecMode(const std::string &secMode)
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
void OPCUA::setSecPolicy(const std::string &secPolicy)
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
void OPCUA::setTraceFile(const std::string &traceFile)
{
	if (traceFile == "True" || traceFile == "true" || traceFile == "TRUE")
	{
		string traceFilePath = getDataDir() + string("/logs/");
		size_t len = traceFilePath.length();
		m_traceFile = (char *)malloc(1 + len);
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
void OPCUA::clearSubscription()
{
	m_subscriptions.clear();
}

/**
 * Add a subscription parent node to the list
 */
void OPCUA::addSubscription(const string &parent)
{
	m_subscriptions.emplace_back(parent);
}

/**
 * Add a set of subscriptions based on the content of m_subscriptions. This
 * is a vector of node ID's
 */
int OPCUA::subscribe()
{
	int res;
	Logger *logger = Logger::getLogger();

	if (!m_connected.load())
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
		try
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
		catch (...)
		{
			logger->error("Unable to read Node %s", it->c_str());
		}
	}
	if (variables.size() == 0)
	{
		logger->error("No variables found to be monitored");
		return 0;
	}

	char **node_ids = (char **)calloc(variables.size(), sizeof(char *));
	if (node_ids == NULL)
	{
		logger->error("Failed to allocate memory for %d subscriptions", variables.size());
		return 0;
	}
	int i = 0;
	for (auto it = variables.cbegin(); it != variables.cend(); it++)
	{
		try
		{
			Node *node = new Node(m_connectionId, variables[i].c_str());
			m_nodes.insert(pair<string, Node *>(variables[i], node));
			logger->debug("Subscribe to Node %s, BrowseName %s", node->getNodeId().c_str(), node->getBrowseName().c_str());
			node_ids[i++] = strdup((char *)it->c_str());

			if (m_includePathAsMetadata)
			{
				std::string fullPath;
				getNodeFullPath(node->getNodeId(), fullPath);
				logger->debug("Path to Node %s [%s]", node->getNodeId().c_str(), fullPath.c_str());
				m_fullPaths.insert(std::pair<std::string,std::string>(node->getNodeId(), fullPath));
			}
		}
		catch (...)
		{
			logger->error("Unable to subscribe to Node %s", it->c_str());
		}
	}
	res = SOPC_ClientHelper_AddMonitoredItems(m_connectionId, node_ids, variables.size(), NULL);
	switch (res)
	{
	case 0:
		logger->info("Added %d Monitored Items", (int)variables.size());
		break;
	case -1:
		logger->error("Failed to add %d Monitored Items, connection not valid", (int)variables.size());
		break;
	case -2:
		logger->error("Failed to add Monitored Items, invalid nodes for %d nodes", (int)variables.size());
		break;
	case -100:
		logger->error("Failed to add %d Monitored Items", (int)variables.size());
		break;
	default:
		logger->error("Failed to add %d Monitored Items, NodeId '%s' not valid", (int)variables.size(), node_ids[abs(res) - 3]);
		break;
	}
	for (i = 0; i < variables.size(); i++)
	{
		if (node_ids[i])
			free(node_ids[i]);
	}
	free(node_ids);
	return res;
}

/**
 * Create nodes for all the parents of the node we subscribe to
 */
void OPCUA::getParents()
{
	for (auto it = m_parents.cbegin(); it != m_parents.cend(); it++)
	{
		try
		{
			Node *node = new Node(m_connectionId, it->second);
			m_parentNodes.insert(pair<string, Node *>(it->first, node));
		}
		catch (...)
		{
			Logger::getLogger()->error("Failed to find parent node with nodeId %s",
									   it->first.c_str());
			// Ignore
		}
	}
}

/**
 * Get the full path of the Node by concatentating all parents up to (but not including) the Objects Folder
 *
 * @param node			The current node to inspect
 * @param path			Full Path to the current node
 */
void OPCUA::getNodeFullPath(const std::string &nodeId, std::string &path)
{
	static char nodeId_ObjectsFolder[] = "i=85";
	static std::string pathDelimiter("/");

	SOPC_ClientHelper_BrowseRequest browseRequest;
	SOPC_ClientHelper_BrowseResult browseResult;

	browseRequest.nodeId = nodeId.c_str();					 // Node to inspect
	browseRequest.direction = OpcUa_BrowseDirection_Inverse; // Inverse is in the direction of the parent
	browseRequest.referenceTypeId = "";						 // all reference types
	browseRequest.includeSubtypes = false;

	Logger::getLogger()->debug("Full Path Browse '%s'", browseRequest.nodeId);
	int res = SOPC_ClientHelper_Browse(m_connectionId, &browseRequest, 1, &browseResult);

	if (res != 0)
	{
		Logger::getLogger()->error("Full Path Browse returned %d for Node %s", res, nodeId.c_str());
		return;
	}
	Logger::getLogger()->debug("Full Path Browse status: %d, nbOfResults: %d", browseResult.statusCode, browseResult.nbOfReferences);

	for (int32_t i = 0; i < browseResult.nbOfReferences; i++)
	{
		Logger::getLogger()->debug("Item #%d: NodeId %s, BrowseName %s, DisplayName %s, RefTypeId %s, NodeClass %s",
								   i, browseResult.references[i].nodeId,
								   browseResult.references[i].browseName,
								   browseResult.references[i].displayName,
								   browseResult.references[i].referenceTypeId,
								   nodeClass(browseResult.references[i].nodeClass).c_str());

		// Stop building the full path when the parent is the top-level Objects folder
		if (strncmp(browseResult.references[i].nodeId, nodeId_ObjectsFolder, strlen(nodeId_ObjectsFolder)) != 0)
		{
			getNodeFullPath(browseResult.references[i].nodeId, path);
			path = path.append(pathDelimiter).append(browseResult.references[i].browseName);
		}

		free(browseResult.references[i].nodeId);
		free(browseResult.references[i].displayName);
		free(browseResult.references[i].browseName);
		free(browseResult.references[i].referenceTypeId);
	}
	free(browseResult.references);
}

/**
 * Starts the plugin
 *
 * We register with the OPC UA server, retrieve all the objects under the parent
 * to which we are subscribing and start the process to enable OPC UA to send us
 * change notifications for those items.
 */
void OPCUA::start()
{
	int n_subscriptions = 0;
	SOPC_ClientHelper_Security security;
	Logger *logger = Logger::getLogger();

	logger->debug("Calling OPCUA::start");
	m_stopped.store(false);
	m_connected.store(false);

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
			logger->fatal("Unable to initialise S2OPC CommonHelper library: %d", (int)initStatus);
			throw runtime_error("Unable to initialise CommonHelper library");
		}

		if (SOPC_ClientHelper_Initialize(disconnect_callback) != 0)
		{
			logger->fatal("Unable to initialise S2OPC ClientHelper library");
			throw runtime_error("Unable to initialise ClientHelper library");
		}

		m_init = true;
	}

	// GetEndPoints is the first method call that attempts to connect to the OPC UA server.
	// If this does not succeed, there is no way to proceed so exit immediately.
	// GetEndPoints will start a connection retry thread.
	SOPC_ClientHelper_GetEndpointsResult *endpoints = GetEndPoints(m_url.c_str());
	if (endpoints == NULL)
	{
		return;
	}

	bool configOK = true; // if true, plugin configuration is valid

	security.security_policy = m_secPolicy.c_str();
	security.security_mode = m_secMode;
	if (m_secMode == OpcUa_MessageSecurityMode_None)
	{
		security.security_policy = SOPC_SecurityPolicy_None_URI;
	}
	logger->debug("Requesting Security Mode '%s', Security Policy '%s'", securityMode(security.security_mode).c_str(), security.security_policy);

	security.policyId = m_authPolicy.c_str();
	if (PolicyIdToUserTokenType(security.policyId) == OpcUa_UserTokenType_Anonymous)
	{
		logger->debug("Requesting anonymous authentication policy");
		security.username = NULL;
		security.password = NULL;
	}
	else
	{
		logger->debug("Requesting username authentication policy");
		security.username = m_username.c_str();
		security.password = m_password.c_str();
	}

	string certstore = getDataDir() + string("/etc/certs/");

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
				configOK = false;
			}
			else
			{
				logger->info("Using CA Certificate %s", security.path_cert_auth);
			}
		}
		else
		{
			security.path_cert_auth = NULL;
			logger->warn("No CA Certificate has been configured");
		}
		if (m_caCrl.length())
		{
			string crl = certstore + m_caCrl + ".der";
			m_path_crl = strdup(crl.c_str());
			security.path_crl = m_path_crl;
			if (access(security.path_crl, R_OK))
			{
				logger->error("Unable to access CRL Certificate %s", security.path_crl);
				configOK = false;
			}
			else
			{
				logger->info("Using CRL Certificate %s", security.path_crl);
			}
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
				configOK = false;
			}
			else
			{
				logger->info("Using Server Certificate %s", security.path_cert_srv);
			}
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
				configOK = false;
			}
			else
			{
				logger->info("Using Client Certificate %s", security.path_cert_cli);
			}
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
					logger->error("Unable to access Client Key %s", security.path_key_cli);
					configOK = false;
				}
				else
				{
					logger->info("Using Client Key %s", security.path_key_cli);
				}
			}
			else
			{
				logger->info("Using Client Key %s", security.path_key_cli);
			}
		}
		else
		{
			security.path_key_cli = NULL;
			logger->warn("No Client Key has been configured");
		}
	}

	// Check for a matching endpoint
	bool matched = false;
	if (endpoints && endpoints->endpoints)
	{
		logger->debug("Endpoint matching starting....");
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
				SOPC_ClientHelper_UserIdentityToken *userIds = endpoints->endpoints[i].userIdentityTokens;
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
						logger->debug("Endpoint %d matches on policyId %s (%d)", i, security.policyId, (int)userIds[j].tokenType);
						matched = true;
					}
					else
					{
						logger->debug("%d: '%s' != '%s' (%d)", i, security.policyId, userIds[j].policyId, (int)userIds[j].tokenType);
						continue;
					}
				}
			}
		}
		if (!matched)
		{
			logger->error("Failed to match any server endpoints with Security Mode '%s', Security Policy '%s', Authentication policy '%s'",
						  securityMode(m_secMode).c_str(), security.security_policy, m_authPolicy.c_str());
			if (!matchedMode)
				logger->error("There are no endpoints that match the security mode requested");
			if (!matchedPolicyURL)
				logger->error("There are no endpoints that match the Policy URL %s",
							  security.security_policy);
			if (!matchedPolicyId)
				logger->error("There are no endpoints that match the Policy Id %s",
							  security.policyId);
		}
		else
		{
			logger->info("Matched Endpoint: Security Mode '%s', Security Policy '%s', Authentication policy '%s'",
						 securityMode(security.security_mode).c_str(), security.security_policy, security.policyId);
		}
	}

	if (configOK && matched)
	{
		m_configurationId = SOPC_ClientHelper_CreateConfiguration(m_url.c_str(), &security, NULL);
		logger->debug("ConfigurationId: %d", (int)m_configurationId);
		if (m_configurationId <= 0)
		{
			logger->error("Failed to create configuration for endpoint '%s' %d", m_url.c_str(), m_configurationId);
			switch (m_configurationId)
			{
			case 0:
				logger->error("Invalid endpointURL %s", m_url.c_str());
				break;
			case -1:
				logger->error("Invalid security detected");
				break;
			case -11:
				logger->error("Invalid Security Policy %s", security.security_policy);
				break;
			case -12:
				logger->error("Invalid Security Mode %d", security.security_mode);
				break;
			case -13:
				logger->error("Invalid CA Certificate %s", security.path_cert_auth);
				break;
			case -14:
				logger->error("Invalid CRL Certificate %s", security.path_crl);
				break;
			case -15:
				logger->error("Invalid Server Certificate %s", security.path_cert_srv);
				break;
			case -16:
				logger->error("Invalid Client Certificate %s", security.path_cert_cli);
				break;
			case -17:
				logger->error("Invalid Client key %s", security.path_key_cli);
				break;
			case -18:
				logger->error("Invalid Policy Id %s", security.policyId);
				break;
			case -19:
				logger->error("Invalid username %s", security.username);
				break;
			case -20:
				logger->error("Invalid password %s", security.password);
				break;
			}
		}
		else
		{
			// ConfigurationId is valid. Create a connection to the OPC UA Server.
			m_connectionId = SOPC_ClientHelper_CreateConnection(m_configurationId);
			if (m_connectionId > 0)
			{
				m_connected.store(true);
				setRetryThread(false);
			}
			else if (m_connectionId == -1)
			{
				m_connected.store(false);
				logger->error("Failed to create OPC/UA connection to server %s, invalid configuration detected", m_url.c_str());
			}
			else if (m_connectionId == -100)
			{
				m_connected.store(false);
				logger->error("Failed to create OPC/UA connection to server %s, connection failed", m_url.c_str());
			}
			else
			{
				m_connected.store(false);
				logger->error("Failed to create OPC/UA connection to server %s, unknown error: %d", m_url.c_str(), (int)m_connectionId);
			}
		}
	} // end if configOK && matched

	FreeEndpointCollection(endpoints);

	if (m_connected.load())
	{
		logger->info("Successfully connected to OPC/UA Server: %s", m_url.c_str());
		subscribe();
		getParents();
		resolveDuplicateBrowseNames();
	}
	else
	{
		logger->warn("Not connected to OPC/UA Server: %s", m_url.c_str());
	}
}

/**
 * Stop all subscriptions and disconnect from the OPCUA server
 */
void OPCUA::stop()
{
	Logger::getLogger()->debug("Calling OPCUA::stop");
	m_stopped.store(true);
	if (m_connected.load())
	{
		SOPC_ClientHelper_Unsubscribe(m_connectionId);
		SOPC_ClientHelper_Disconnect(m_connectionId);
		m_connectionId = 0;
		m_connected.store(false);
	}
	if (m_init)
	{
		SOPC_ClientHelper_Finalize();
		SOPC_CommonHelper_Clear();
		m_init = false;
	}
	// Cleanup memory
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

	Logger::getLogger()->debug("Leaving OPCUA::stop");
}

/**
 * Called when a data changed event is received. This calls back to the south service
 * and adds the points to the readings queue to send.
 *
 * @param points    The points in the reading we must create
 * @param ts	    The timestamp of the data
 * @param object    The name of the parent object
 */
void OPCUA::ingest(vector<Datapoint *> points, const timeval &user_ts, const string &object)
{
	string asset = m_asset + points[0]->getName();

	switch (m_assetNaming)
	{
	case ASSET_NAME_SINGLE:
		asset = m_asset + points[0]->getName();
		break;
	case ASSET_NAME_SINGLE_OBJ:
		asset = object + points[0]->getName();
		break;
	case ASSET_NAME_OBJECT:
		asset = object;
		break;
	case ASSET_NAME:
		asset = m_asset;
		break;
	}
	Reading rdng(asset, points);
	rdng.setUserTimestamp(user_ts);
	(*m_ingest)(m_data, rdng);
}

/**
 * Get a list of available endpoints from the OPC UA Server
 *
 * @param endPointUrl	OPC UA Server Url
 */
SOPC_ClientHelper_GetEndpointsResult *OPCUA::GetEndPoints(const char *endPointUrl)
{
	Logger *logger = Logger::getLogger();

	SOPC_ClientHelper_GetEndpointsResult *endpoints = NULL;
	try
	{
		int res = SOPC_ClientHelper_GetEndpoints(endPointUrl, &endpoints);
		if (res == 0)
		{
			logger->debug("OPC/UA Server has %d endpoints\n", endpoints->nbOfEndpoints);

			for (int32_t i = 0; i < endpoints->nbOfEndpoints; i++)
			{
				logger->debug("%d - url: %s\n", i, endpoints->endpoints[i].endpointUrl);
				logger->debug("%d - security level: %d\n", i, endpoints->endpoints[i].securityLevel);
				logger->debug("%d - security mode: %d\n", i, endpoints->endpoints[i].security_mode);
				logger->debug("%d - security policy Uri: %s\n", i, endpoints->endpoints[i].security_policyUri);
				logger->debug("%d - transport profile Uri: %s\n", i, endpoints->endpoints[i].transportProfileUri);

				SOPC_ClientHelper_UserIdentityToken *userIds = endpoints->endpoints[i].userIdentityTokens;
				for (int32_t j = 0; j < endpoints->endpoints[i].nbOfUserIdentityTokens; j++)
				{
					logger->debug("%d %d - policy Id: %s\n", i, j, userIds[j].policyId);
					logger->debug("%d %d - token type: %d\n", i, j, userIds[j].tokenType);
					logger->debug("%d %d - issued token type: %s\n", i, j, userIds[j].issuedTokenType);
					logger->debug("%d %d - issuer endpoint Url: %s\n", i, j, userIds[j].issuerEndpointUrl);
					logger->debug("%d %d - security policy Uri: %s\n", i, j, userIds[j].securityPolicyUri);
				}
			}
		}
		else
		{
			// If GetEndpoints fails, uninitialise the S2OPCUA Toolkit.
			// If this is not done, an S2OPCUA background thread will throw an exception that we can't catch.
			if (m_init)
			{
				SOPC_ClientHelper_Finalize();
				SOPC_CommonHelper_Clear();
				m_init = false;
			}

			logger->error("Error %d retrieving endpoints from OPC/UA Server: %s", res, endPointUrl);

			// Start the connection retry thread.
			m_connectionId = 0;
			m_connected.store(false);
			setRetryThread(true);
		}
	}
	catch (const std::exception &e)
	{
		logger->error("GetEndPoints Exception: %s", e.what());
	}

	return endpoints;
}

/**
 * Construct a node class for the given nodeID
 *
 * @param conn		The connection to the OPCUA server
 * @param nodeId	The ID of the node to read
 */
OPCUA::Node::Node(uint32_t conn, const string &nodeId) : m_nodeID(nodeId)
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
		Logger::getLogger()->error("Failed to read Node \"%s\", %d", nodeId.c_str(), res);
		throw runtime_error("Failed to read node");
	}
}

/**
 * We have detected two browse names that are the same. Resolve this
 * by adding the nodeID to the browse name.
 */
void OPCUA::Node::duplicateBrowseName()
{
	m_browseName.append(".");
	m_browseName.append(m_nodeID);
}

/**
 * Browse a node and add to the subscription list if it is a variable.
 * If it is a FolderType then recurse down the child nodes
 *
 * @param nodeid	NodeId of the candidate to subscribe to
 * @param variables	Vector of variable node ID's
 */
void OPCUA::browse(const string &nodeid, vector<string> &variables)
{
	int res;

	SOPC_ClientHelper_BrowseRequest browseRequest;
	SOPC_ClientHelper_BrowseResult browseResult;

	browseRequest.nodeId = (char *)nodeid.c_str();			 // Root/Objects/
	browseRequest.direction = OpcUa_BrowseDirection_Forward; // forward
	browseRequest.referenceTypeId = "";						 // all reference types
	browseRequest.includeSubtypes = true;

	Logger::getLogger()->debug("Browse '%s'", browseRequest.nodeId);
	/* Browse specified node */
	res = SOPC_ClientHelper_Browse(m_connectionId, &browseRequest, 1, &browseResult);

	if (res != 0)
	{
		Logger::getLogger()->info("Browse returned %d for Node %s", res, nodeid.c_str());
		return;
	}
	Logger::getLogger()->debug("status: %d, nbOfResults: %d", browseResult.statusCode, browseResult.nbOfReferences);

	if (browseResult.nbOfReferences == 0)
	{
		Logger::getLogger()->error("Unable to locate the OPCUA Node '%s'", nodeid.c_str());
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
			m_parents.insert(pair<string, string>(browseResult.references[i].nodeId, nodeid));
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
void OPCUA::disconnect(const uint32_t connectionId)
{
	if (m_stopped.load())
		Logger::getLogger()->info("OPC/UA Client %d disconnected", (int)connectionId);
	else
		Logger::getLogger()->warn("OPC/UA Client %d disconnected", (int)connectionId);

	m_connected.store(false);
	if (!m_stopped.load())
	{
		// This was not a user initiated stop.
		// Stop the retry thread if it is running.
		// Briefly set m_stopped to 'true' to allow the retry thread to exit.
		m_stopped.store(true);
		setRetryThread(false);
		m_stopped.store(false);
	}
}

/**
 * This method is run in a background thread to retry the connection to the OPC UA server
 * after a loss of connection. If a connection is re-established or if the plugin
 * is shutting down, this method will exit.
 *
 * There will be a delay between retries starting at 2 seconds and
 * backing off to once per minute.
 */
void OPCUA::retry()
{
	Logger::getLogger()->debug("OPCUA::retry thread open");

	static int oneminute = 60;
	int delay = 2;
	std::this_thread::sleep_for(std::chrono::seconds(delay));
	m_configMutex.lock();

	while (!m_connected.load() && !m_stopped.load())
	{
		try
		{
			Logger::getLogger()->debug("OPCUA::retry before start");
			start();
			Logger::getLogger()->debug("OPCUA::retry after start: Delay: %d Connected: %d Stopped: %d", delay, (int)m_connected.load(), (int)m_stopped.load());
		}
		catch (std::exception ex)
		{
			Logger::getLogger()->error("OPCUA::retry exception: %s", ex.what());
		}

		delay *= 2;
		if (delay > oneminute)
		{
			delay = oneminute;
		}

		// Unlock the mutex while waiting.
		// This will allow reconfiguration or shutdown to take place in the main thread.
		m_configMutex.unlock();
		int numSeconds = 0;
		while (!m_connected.load() && !m_stopped.load() && (numSeconds < delay))
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
			numSeconds++;
		}
		m_configMutex.lock();
	}
	m_configMutex.unlock();
	Logger::getLogger()->debug("OPCUA::retry thread close");
}

/**
 * Start or stop the retry thread
 *
 * @param start		If true, start the thread. If false, stop the thread.
 */
void OPCUA::setRetryThread(bool start)
{
	Logger::getLogger()->debug("OPCUA::setRetryThread(%d)", (int)start);

	if (start)
	{
		if (m_background == NULL)
		{
			m_background = new thread(retryThread, this);
			Logger::getLogger()->debug("OPCUA::setRetryThread: retry thread started");
		}
	}
	else
	{
		if (m_background && m_background->joinable())
		{
			m_background->join();
			Logger::getLogger()->debug("OPCUA::setRetryThread: retry thread stopped");
		}
		m_background = NULL;
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
	return string("Unknown");
}

/**
 * Set the desired asset naming scheme from the configuration
 * item
 *
 * @param scheme	Required asset naming scheme
 */
void OPCUA::setAssetNaming(const string &scheme)
{
	if (scheme.compare("Single datapoint") == 0)
	{
		m_assetNaming = ASSET_NAME_SINGLE;
	}
	else if (scheme.compare("Single datapoint object prefix") == 0)
	{
		m_assetNaming = ASSET_NAME_SINGLE_OBJ;
	}
	else if (scheme.compare("Asset per object") == 0)
	{
		m_assetNaming = ASSET_NAME_OBJECT;
	}
	else if (scheme.compare("Single asset") == 0)
	{
		m_assetNaming = ASSET_NAME;
	}
	else
	{
		m_assetNaming = ASSET_NAME_SINGLE;
	}
}

/**
 * Resolve duplicate browse names within nodes, if the naming
 * scheme we are using includes the parent object name in the
 * naming we ignore duplicates as they are always going to have
 * different parent nodes.
 */
void OPCUA::resolveDuplicateBrowseNames()
{
	if (m_assetNaming == ASSET_NAME_SINGLE_OBJ || m_assetNaming == ASSET_NAME_OBJECT)
	{
		return;
	}
	for (auto it = m_nodes.begin(); it != m_nodes.end(); ++it)
	{
		string b1 = it->second->getBrowseName();
		auto it2 = ++it;
		it--;
		while (it2 != m_nodes.end())
		{
			string b2 = it2->second->getBrowseName();
			if (b1.compare(b2) == 0)
			{
				it->second->duplicateBrowseName();
				it2->second->duplicateBrowseName();
			}
			it2++;
		}
	}
}
