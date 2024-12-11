/*
 * Fledge S2OPCUA South service plugin
 *
 * Copyright (c) 2021-2024 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora, Ray Verhoeff
 */

#include <opcua.h>
#include <string.h>
#include <reading.h>
#include <logger.h>
#include <map>
#include <unistd.h>
#include <chrono>
#include <math.h>
#include <regex>
#include <file_utils.h>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;

static OPCUA *opcua = NULL;

/**
 * Callback routine to return username and password to the S2OPC Toolkit.
 * This callback must allocate memory which will be freed by the Toolkit.
 *
 * @param outUsername	returned username
 * @param outPassword	returned password
 * @return				return true if successful
 */
static bool UsernamePasswordCallback(char** outUsername, char** outPassword)
{
	std::string &username =  opcua->getUsername();

	if (username.empty())
	{
		*outUsername = NULL;
		*outPassword = NULL;
	}
	else
	{
		char* usr = (char *) SOPC_Calloc(sizeof(char), 1 + username.length());
		strncpy(usr, username.c_str(), username.length());
		usr[username.length()] = '\0';

		std::string &password =  opcua->getPassword();
		char* pwd = (char *) SOPC_Calloc(sizeof(char), 1 + password.length());
		strncpy(pwd, password.c_str(), password.length());
		pwd[password.length()] = '\0';

		*outUsername = usr;
		*outPassword = pwd;

		Logger::getLogger()->debug("UsernamePasswordCallback: username '%s'", username.c_str());
	}

    return true;
}

/**
 * Create the PKI directory tree required by the S2OPC Toolkit.
 *
 * @param instanceName	Name of the plugin service instance
 * @param logger		Fledge Logger object
 * @return				Zero if successful, otherwise -1
 */
static int createDirectories(const std::string &instanceName, Logger *logger)
{
	int stat = 0;

	try
	{
		std::string path = getDataDir() + "/tmp";
		createDirectory(path);

		path.append("/s2opcua");
		createDirectory(path);

		path.append("/").append(instanceName);
		createDirectory(path);

		std::string pkiRoot = path.append("/pki");
		createDirectory(pkiRoot);

		path = pkiRoot + "/issuers";
		createDirectory(path);

		path = pkiRoot + "/issuers/certs";
		createDirectory(path);

		path = pkiRoot + "/issuers/crl";
		createDirectory(path);

		path = pkiRoot + "/trusted";
		createDirectory(path);

		path = pkiRoot + "/trusted/certs";
		createDirectory(path);

		path = pkiRoot + "/trusted/crl";
		createDirectory(path);
	}
	catch (std::exception e)
	{
		logger->error("createDirectories: %s", e.what());
		stat = -1;
	}

	return stat;
}

/**
 * Callback for change in S2OPC Toolkit connection status.
 * 
 * In S2OPC Toolkit 1.5.0, 'SOPC_ClientConnectionEvent_Disconnected' is the only event generated.
 *
 * @param instanceName	Name of the plugin service instance
 * @param logger		Fledge Logger object
 * @return				Zero if successful, otherwise -1
 */
static void ClientConnectionEvent(SOPC_ClientConnection *config,
								  SOPC_ClientConnectionEvent event,
								  SOPC_StatusCode status)
{
	SOPC_UNUSED_ARG(config);

	switch (event)
	{
	case SOPC_ClientConnectionEvent_Disconnected:
		if (SOPC_IsGoodStatus(status))
		{
			Logger::getLogger()->warn("Disconnection event received");
		}
		else
		{
			Logger::getLogger()->error("Disconnection event received with error 0x%08X", status);
		}
		opcua->disconnect();
		break;
	case SOPC_ClientConnectionEvent_Connected:
	case SOPC_ClientConnectionEvent_Reconnecting:
	default:
		Logger::getLogger()->warn("ClientConnectionEvent Error 0x%08X: Unexpected connection event %d", status, (int)event);
		break;
	}
}

/**
 * Callback when Monitored Item values are received by a Subscription
 * 
 * @param subscription		Subscription that received Monitored Item data changes
 * @param status			Publish service ResponseHeader ServiceResult
 * @param notificationType	Type of notification received
 * @param nbNotifElts		Number of items in the notification Monitored Items and monitoredItemCtxArray arrays
 * @param notification		Notification of type indicated by notificationType
 * @param monitoredItemCtxArray	Array of context objects for the Monitored Items
 */
static void subscriptionCallback(const SOPC_ClientHelper_Subscription *subscription,
								 SOPC_StatusCode status,
								 SOPC_EncodeableType *notificationType,
								 uint32_t nbNotifElts,
								 const void *notification,
								 uintptr_t *monitoredItemCtxArray)
{
	SOPC_UNUSED_ARG(subscription);
	if (SOPC_IsGoodStatus(status))
	{
		if (notificationType && notificationType == &OpcUa_DataChangeNotification_EncodeableType)
		{
			OpcUa_DataChangeNotification *dataChanges = (OpcUa_DataChangeNotification *)notification;
			for (uint32_t i = 0; i < nbNotifElts; i++)
			{
				opcua->dataChange((char *)monitoredItemCtxArray[i], &dataChanges->MonitoredItems[i].Value);
			}
		}
		else
		{
			Logger::getLogger()->warn("Data Change Notification unexpected type %u", notificationType ? notificationType->TypeId : 0);
		}
	}
	else if (opcua->readyForData())
	{
		// Log an error message only if the plugin should be processing data.
		// If no new data values are available when the S2OPC Toolkit makes a Publish request,
		// the Service Result is 'OpcUa_BadNothingToDo' which is not an error.
		if (status == OpcUa_BadNothingToDo)
		{
			opcua->incrementNothingToDo();
		}
		else
		{
			Logger::getLogger()->error("Data Change Notification error 0x%08X", status);
		}
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
 * Determine whether a Reference Type is a valid parent when
 * creating a full OPC UA path to a Variable
 *
 * @param referenceId	Reference Type to be examined
 * @return isValid		If true, reference type represents a valid parent
 */
static bool IsValidParentReferenceId(const SOPC_NodeId *referenceId)
{
	static uint32_t validIdentifiers[] = {
		OpcUaId_Organizes,				// i=35: Organizes/OrganizedBy
		OpcUaId_HasProperty,			// i=46: HasProperty/PropertyOf
		OpcUaId_HasComponent,			// i=47: HasComponent/ComponentOf
		OpcUaId_HasOrderedComponent,	// i=49: HasOrderedComponent/OrderedComponentOf
		0
	};
	
	if (referenceId == NULL) return false;
	bool found = false;
	int i = 0;
	
	while (validIdentifiers[i] > 0)
	{
		SOPC_NodeId validReferenceId = {
			.IdentifierType = SOPC_IdentifierType_Numeric,
			.Namespace = 0,
			validReferenceId.Data.Numeric = validIdentifiers[i]
		};
		
		int32_t comparison = 0;
		SOPC_ReturnStatus status = SOPC_NodeId_Compare(referenceId, &validReferenceId, &comparison);
		
		if ((status == SOPC_STATUS_OK) && (comparison == 0))
		{
			found = true;
			break;
		}
		
		i++;
	}
	
	return found;
}

/**
 * Determine the Data Change Filter Trigger Type from a string
 *
 * @param triggerTypeString	Data Change Filter Trigger Type string
 * @return Data Change Filter Trigger Type
 */
static OpcUa_DataChangeTrigger dcfTriggerType(const std::string &triggerTypeString)
{
	if (triggerTypeString.compare("Status") == 0)
		return OpcUa_DataChangeTrigger_Status;
	else if (triggerTypeString.compare("Status + Value") == 0)
		return OpcUa_DataChangeTrigger_StatusValue;
	else if (triggerTypeString.compare("Status + Value + Timestamp") == 0)
		return OpcUa_DataChangeTrigger_StatusValueTimestamp;
	else
	{
		return OpcUa_DataChangeTrigger_SizeOf;
	}
}

/**
 * Generate a string representation of Data Change Filter Trigger Type
 *
 * @param triggerType	Data Change Filter Trigger Type
 * @return Data Change Filter Trigger Type string
 */
static std::string dcfTriggerType(const OpcUa_DataChangeTrigger triggerType)
{
	switch (triggerType)
	{
	case OpcUa_DataChangeTrigger_Status:
		return std::string("Status");
	case OpcUa_DataChangeTrigger_StatusValue:
		return std::string("Status + Value");
	case OpcUa_DataChangeTrigger_StatusValueTimestamp:
		return std::string("Status + Value + Timestamp");
	default:
		return std::string("Unknown");
	}
}

/**
 * Determine the Data Change Filter Deadband Type from a string
 *
 * @param deadbandTypeString	Data Change Filter Deadband Type string
 * @return Data Change Filter Deadband Type
 */
static OpcUa_DeadbandType dcfDeadbandType(const std::string &deadbandTypeString)
{
	if (deadbandTypeString.compare("None") == 0)
		return OpcUa_DeadbandType_None;
	else if (deadbandTypeString.compare("Absolute") == 0)
		return OpcUa_DeadbandType_Absolute;
	else if (deadbandTypeString.compare("Percent") == 0)
		return OpcUa_DeadbandType_Percent;
	else
	{
		return OpcUa_DeadbandType_SizeOf;
	}
}

/**
 * Generate a string representation of Data Change Filter Deadband Type
 *
 * @param deadbandTypeString	Data Change Filter Deadband Type
 * @return Data Change Filter Deadband Type string
 */
static std::string dcfDeadbandType(const OpcUa_DeadbandType deadbandType)
{
	switch (deadbandType)
	{
	case OpcUa_DeadbandType_None:
		return std::string("None");
	case OpcUa_DeadbandType_Absolute:
		return std::string("Absolute");
	case OpcUa_DeadbandType_Percent:
		return std::string("Percent");
	default:
		return std::string("Unknown");
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
	if (m_stopped.load() || !m_readyForData.load())
	{
		return;
	}

	DatapointValue *dpv = NULL;

	setRetryThread(false);
	if ((value->Status & SOPC_DataValueOverflowStatusMask) == SOPC_DataValueOverflowStatusMask)
	{
		Logger::getLogger()->warn("NodeId %s: DataValueOverflow", nodeId);
		m_numOpcUaOverflows++;
	}

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
				if (variant.Value.String.Length > 0 && variant.Value.String.Data != NULL)
				{
					string str = SOPC_String_GetRawCString(&variant.Value.String);
					dpv = new DatapointValue(str);
				}
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
			Logger::getLogger()->debug("DataChange: %s,%s,%s", DateTimeToString(value->SourceTimestamp).c_str(), dpv->toString().c_str(), nodeId);
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
			delete dpv;
			dpv = NULL;

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
				delete dpv;
				dpv = NULL;
			}

			ingest(points, tm_userts, parent);
			m_numOpcUaValues++;
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
				 m_reportingInterval(100),
				 m_miBlockSize(100),
				 m_maxKeepalive(30),
				 m_numOpcUaValues(0),
				 m_numOpcUaOverflows(0),
				 m_numOpcUaNothingToDo(0),
				 m_tstart(0),
				 m_totalElapsedSeconds(0),
				 m_numNodeIds(0),
				 m_nodeIds(NULL),
				 m_background(NULL),
				 m_init(false),
				 m_traceFile(NULL),
				 m_connection(NULL),
				 m_subscription(NULL),
				 m_assetNaming(ASSET_NAME_SINGLE),
				 m_secMode(OpcUa_MessageSecurityMode_Invalid),
				 m_dcfEnabled(false),
				 m_dcfTriggerType(OpcUa_DataChangeTrigger_StatusValue),
				 m_dcfDeadbandType(OpcUa_DeadbandType_None),
				 m_dcfDeadbandValue(0.0)

{
	m_connected.store(false);
	m_stopped.store(false);
	m_readyForData.store(false);
	opcua = this;
	updateS2parameters();
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
 * Clear OPCUA object members that are loaded from plugin configuration
 */
void OPCUA::clearConfig()
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
	m_filterRegex.clear();
	m_subscriptions.clear();
	m_metaDataName.clear();
	m_includePathAsMetadata = false;
	m_assetNaming = ASSET_NAME_SINGLE;
	m_reportingInterval = 100;
	m_publishPeriod = 1000;
	m_maxKeepalive = 30;
	m_miBlockSize = 100;
	m_secMode = OpcUa_MessageSecurityMode_Invalid;
	m_dcfEnabled = false;
	m_dcfTriggerType = OpcUa_DataChangeTrigger_StatusValue;
	m_dcfDeadbandType = OpcUa_DeadbandType_None;
	m_dcfDeadbandValue = 0.0;

	if (m_traceFile)
	{
		free(m_traceFile);
		m_traceFile = NULL;
	}
}

/**
 * Clear OPCUA object members that are internal lists and indexes
 */
void OPCUA::clearData()
{
	m_fullPaths.clear();
	m_lastIngest.clear();
	m_parents.clear();
	m_parentNodes.clear();

	for (Node *node : m_nodeObjects)
	{
		delete node;
	}
	m_nodeObjects.clear();

	for (pair<string, Node *> item : m_nodes)
	{
		delete item.second;
	}
	m_nodes.clear();

	if (m_nodeIds)
	{
		for (size_t i = 0; i < m_numNodeIds; i++)
		{
			if (m_nodeIds[i])
			{
				free(m_nodeIds[i]);
			}
		}
		free(m_nodeIds);
		m_nodeIds = NULL;
	}
}

/**
 * Check regex validity
 *
 * @param	regexp	Regular expression
 * @return	bool	true if regex is valid, false otherwise
 */
bool OPCUA::isRegexValid(const std::string &regexp)
{
    try {
        regex re(regexp);
    }
    catch (const std::regex_error& ex) {
		Logger::getLogger()->error("RegEx parse error: %s", ex.what());
        return false;
    }
    return true;
}

/**
 * Parse plugin configuration
 *
 * @param config	configuration information
 */
void OPCUA::parseConfig(ConfigCategory &config)
{
	clearConfig();

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

	if (config.itemExists("miBlockSize"))
	{
		m_miBlockSize = strtol(config.getValue("miBlockSize").c_str(), NULL, 10);
	}
	else
	{
		m_miBlockSize = 100;
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

	setFilterEnabled(false);

	if (config.itemExists("filterRegex"))
	{
		string val = config.getValue("filterRegex");
		if (!val.empty() & isRegexValid(val))
		{
			setFilterRegex(val);
			setFilterEnabled(true);
			Logger::getLogger()->info("Filter regex set to '%s' ", val.c_str());
		}
		else
		{
			Logger::getLogger()->warn("Invalid filter regex '%s' in config, disabling filtering", val.c_str());
			setFilterEnabled(false);
		}
	}

	if (config.itemExists("filterScope"))
	{
		string val = config.getValue("filterScope");
		NodeFilterScope rv = OPCUA::NodeFilterScope::SCOPE_INVALID;
		if (!val.empty())
			rv = setFilterScope(val);
		
		if (rv == OPCUA::NodeFilterScope::SCOPE_INVALID)
		{
			Logger::getLogger()->warn("Invalid filter scope '%s' in config, disabling filtering", val.c_str());
			setFilterEnabled(false);
		}
		else
			Logger::getLogger()->info("Filter scope set to '%s' ", val.c_str());
	}

	if (config.itemExists("filterAction"))
	{
		string val = config.getValue("filterAction");
		NodeFilterAction rv = OPCUA::NodeFilterAction::ACTION_INVALID;
		if (!val.empty())
			rv = setFilterAction(val);
		
		if (rv == OPCUA::NodeFilterAction::ACTION_INVALID)
		{
			Logger::getLogger()->warn("Invalid filter action '%s' in config, disabling filtering", val.c_str());
			setFilterEnabled(false);
		}
		else
			Logger::getLogger()->info("Filter action set to '%s' ", val.c_str());
	}

	if (config.itemExists("dcfEnabled"))
	{
		if (config.getValue("dcfEnabled").compare("true") == 0)
		{
			m_dcfEnabled = true;
		}
	}

	if (config.itemExists("dcfTriggerType"))
	{
		m_dcfTriggerType = dcfTriggerType(config.getValue("dcfTriggerType"));
	}

	if (config.itemExists("dcfDeadbandType"))
	{
		m_dcfDeadbandType = dcfDeadbandType(config.getValue("dcfDeadbandType"));
	}

	if (config.itemExists("dcfDeadbandValue"))
	{
		m_dcfDeadbandValue = std::stod(config.getValue("dcfDeadbandValue"));
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

	Logger::getLogger()->info("OPC UA plugin reconfiguration in progress...");
	opcua->stop();
	opcua->parseConfig(config);
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
		string logDirectory = getDataDir() + string("/logs");
		if (access(logDirectory.c_str(), W_OK))
		{
			mkdir(logDirectory.c_str(), 0777);
		}
		string traceFilePath = getDataDir() + string("/logs/debug-trace/");
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
 * Returns whether Node is to be subscribed to, as per filtering config
 *
 * @param 	browseName	Browse Name of the OPCUA node
 * @param 	nodeClass	Node class of the OPCUA node
 * @param 	isDirectlySubscribed	Is the node present in the subscription
 *                                    map in plugin config
 * @return	subscribeNode	If true, node should be subscribed to
 */
bool OPCUA::checkFiltering(const std::string& browseName, OpcUa_NodeClass nodeClass, bool isDirectlySubscribed)
{
	// if filtering is disabled, always subscribe to given node
	if(!getFilterEnabled())
	{
		Logger::getLogger()->debug("Node '%s': FILTERING IS DISABLED", browseName.c_str());
		return true;
	}

	OPCUA::NodeFilterScope filterScope = getFilterScope();

	// No check is required in case of a directly subscribed variable when filterScope is SCOPE_OBJECT
	if( (nodeClass == OpcUa_NodeClass_Variable) && isDirectlySubscribed && 
				 (filterScope == OPCUA::NodeFilterScope::SCOPE_OBJECT) )
	{
		Logger::getLogger()->debug("Node '%s': Bypassing filtering check in case of directly subscribed "
									"variables when filterScope is SCOPE_OBJECT", browseName.c_str());
		return true;
	}

	// No check is required in case of objects when filterScope is SCOPE_VARIABLE; just browse all objects
	if( (nodeClass == OpcUa_NodeClass_Object) && (filterScope == OPCUA::NodeFilterScope::SCOPE_VARIABLE) )
	{
		Logger::getLogger()->debug("Node '%s': Bypassing filtering check in case of objects when filterScope"
									" is SCOPE_VARIABLE", browseName.c_str());
		return true;
	}

	bool includeNode = (getFilterAction() == OPCUA::NodeFilterAction::INCLUDE);
	
	bool scopeMatch = ((nodeClass == OpcUa_NodeClass_Object && 
						(filterScope == OPCUA::NodeFilterScope::SCOPE_OBJECT || filterScope == OPCUA::NodeFilterScope::SCOPE_OBJECT_VARIABLE)) ||
						(nodeClass == OpcUa_NodeClass_Variable));  // no need to check scope in case of variables; won't reject a variable irrespective of filter scope
	
	if (scopeMatch)
	{
		string filterRegex = getFilterRegex();
		regex re(filterRegex);
		bool match = std::regex_match(browseName, re);
		Logger::getLogger()->debug("filterAction=%s, filterScope=%s, nodeClass=%s, scopeMatch=%s, browseName=%s,"
									" filterRegex=%s, match=%s, subscribe=%s",
										getFilterActionStr().c_str(), getFilterScopeStr().c_str(), nodeClassStr(nodeClass).c_str(), 
										scopeMatch?"TRUE":"FALSE", browseName.c_str(), filterRegex.c_str(),
										match?"TRUE":"FALSE", (includeNode == match)?"TRUE":"FALSE");
		return (includeNode == match);
		
		// include - regex match - subscribe
		// include - regex not matched - no subscribe

		// exclude - regex match - no subscribe
		// exclude - regex not matched - subscribe
	}
	else
	{
		Logger::getLogger()->debug("filterAction=%s, filterScope=%s, nodeClass=%s, scopeMatch=%s, browseName=%s, subscribe=%s",
										getFilterActionStr().c_str(), getFilterScopeStr().c_str(), nodeClassStr(nodeClass).c_str(), 
										scopeMatch?"TRUE":"FALSE", browseName.c_str(), (!includeNode)?"TRUE":"FALSE");
		return !includeNode;
		// scope mismatch - include - can't include
		// scope mismatch - exclude - ok to include
	}
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
 * is a vector of node IDs
 */
int OPCUA::subscribe()
{
	Logger *logger = Logger::getLogger();

	if (!m_connected.load())
	{
		logger->error("Attempt to subscribe aborted, no connection to the OPC UA server");
		return 1;
	}
	
	vector<string> variables;
	std::set<string> objectNodes;

	for (auto it = m_subscriptions.cbegin(); it != m_subscriptions.cend(); it++)
	{
		auto res = m_nodes.find(*it);
		Node *node = NULL;
		if (res == m_nodes.end())
		{
			node = new Node(m_connection, *it);
			if (node->getNodeClass() == OpcUa_NodeClass_Unspecified)
			{
				// A NodeId in the configured OPC UA Object Subscriptions list is not found in the OPC UA Server's Address Space
				logger->error("Subscription NodeId '%s' not found in the Address Space", node->getNodeId().c_str());
				delete node;
				continue;
			}
		}
		else
		{
			node = res->second;
		}

		bool processNode = checkFiltering(node->getBrowseName(), node->getNodeClass(), true);
		if(!processNode)
		{
			logger->warn("Skipping subscription for node '%s' because of filtering config", it->c_str());
			if (res == m_nodes.end())
				delete node;
			
			continue;
		}
		
		try
		{
			if (node->getNodeClass() == OpcUa_NodeClass_Variable)
			{
				variables.push_back(*it);
				m_nodes[*it] = node;
			}
			else if (node->getNodeClass() == OpcUa_NodeClass_Object)
			{
				delete node;
				objectNodes.emplace(*it);
				browseObjects(*it, objectNodes);
			}
			else
			{
				delete node;
				logger->error("Node %s has invalid NodeClass %s", it->c_str(), nodeClassStr(node->getNodeClass()).c_str());
			}
			
		}
		catch (...)
		{
			logger->error("Unable to read Node %s", it->c_str());
		}
	}

	logger->info("Total Objects found: %u", objectNodes.size());
	for (string objectNodeId : objectNodes)
	{
		logger->debug("..Object %s", objectNodeId.c_str());
	}
	for (string objectNodeId : objectNodes)
	{
		browseVariables(objectNodeId, variables);
	}
	
	if (variables.size() == 0)
	{
		logger->error("No variables found to be monitored");
		return 0;
	}

	m_nodeIds = (char **)calloc(variables.size(), sizeof(char *));
	
	if (m_nodeIds == NULL)
	{
		logger->error("Failed to allocate memory for %u subscriptions", variables.size());
		return 2;
	}
	memset((void *) m_nodeIds, 0, variables.size() * sizeof(char *));

	logger->info("Begin processing %u Variables", variables.size());
	
	int i = 0;
	for (auto it = variables.cbegin(); it != variables.cend(); it++)
	{
		auto res = m_nodes.find(*it);
		Node *node = NULL;
		if (res == m_nodes.end())
		{
			node = new Node(m_connection, *it);
			if (node->getNodeClass() == OpcUa_NodeClass_Unspecified)
			{
				logger->error("Variable NodeId '%s' not found in the Address Space", node->getNodeId().c_str());
				delete node;
				continue;
			}
		}
		else
			node = res->second;
		
		bool processNode = true;  // include child node by default if they are variables
		
		// If parent node is being subscribed to, children variable nodes are also subscribed to
		// And, if the child node is an object, it is evaluated independently as per configured filter
		if(node->getNodeClass() != OpcUa_NodeClass_Variable)
		{
			processNode = checkFiltering(node->getBrowseName(), node->getNodeClass(), false);
		}
		
		if(!processNode)
		{
			logger->warn("Skipping subscription for node '%s' because of filtering config", it->c_str());
			if (res == m_nodes.end())
				delete node;
			
			continue;
		}
		else
			m_nodes[*it] = node;
		
		try
		{
			m_nodeIds[i++] = strdup((char *)it->c_str());
			logger->debug("****** Added m_nodeIds[%d]='%s' ", i-1, m_nodeIds[i-1]);

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

	SOPC_ReturnStatus status = SOPC_STATUS_OK;
	if ((status = createS2Subscription()) == SOPC_STATUS_OK)
	{
		logger->info("Subscription created");
	}
	else
	{
		logger->error("Error %d creating Subscription", (int)status);
		return (int)status;
	}

	if (m_dcfEnabled)
	{
		logger->info("DataChangeFilter: Trigger Type: '%s' Deadband Type: '%s' Deadband: %.3f",
								   dcfTriggerType(m_dcfTriggerType).c_str(), dcfDeadbandType(m_dcfDeadbandType).c_str(), m_dcfDeadbandValue);
	}

	m_numNodeIds = i;
	size_t actualMonitoredItems = 0;
	size_t miBlockSize = (size_t)m_miBlockSize;
	int callCount = 0;
	i = 0;
	bool logRevisions = true;
	bool done = false;
	do
	{
		size_t numNodeIdsToAdd = miBlockSize;
		if (i + numNodeIdsToAdd >= m_numNodeIds)
		{
			numNodeIdsToAdd = m_numNodeIds - i;
			done = true;
		}

		size_t numMonitoredItemErrors = 0;
		logger->debug("createS2MonitoredItems call: i=%d, numNodeIdsToAdd=%d, totalMonitoredItems=%u, m_nodes.size()=%u", i, numNodeIdsToAdd, m_numNodeIds, m_nodes.size());
		if ((status = createS2MonitoredItems(&m_nodeIds[i], numNodeIdsToAdd, logRevisions, &numMonitoredItemErrors)) == SOPC_STATUS_OK)
		{
			actualMonitoredItems += (numNodeIdsToAdd - numMonitoredItemErrors);
			logRevisions = false;
		}

		callCount++;
		i += miBlockSize;

	} while (!done && !m_stopped.load() && (status == SOPC_STATUS_OK));

	if (status == SOPC_STATUS_OK)
	{
		logger->info("Added %u Monitored Items in %d calls",  actualMonitoredItems, callCount);
		m_readyForData.store(true);
		m_tstart = time(0);
	}
	else
	{
		logger->error("Error %d adding Monitored Items. Items added: %u of %u. CallCount: %d", status, actualMonitoredItems, m_numNodeIds, callCount);
	}
	
	return (int)status;
}

/**
 * Initialise the S2OPC Toolkit
 *
 * @param traceFilePath	Full path of the trace file. If NULL, do not create a trace file.
 * @return				S2OPC status code
 */
SOPC_ReturnStatus OPCUA::initializeS2sdk(const char *traceFilePath)
{
	SOPC_ReturnStatus initStatus = SOPC_STATUS_OK;

	if (m_init == false)
	{
		m_connection = NULL;
		m_subscription = NULL;

		SOPC_Log_Configuration logConfig = SOPC_Common_GetDefaultLogConfiguration();
		if (traceFilePath && strlen(traceFilePath))
		{
			logConfig.logSysConfig.fileSystemLogConfig.logDirPath = traceFilePath;
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
			Logger::getLogger()->fatal("Unable to initialise S2OPC CommonHelper library: %d", (int)initStatus);
			throw runtime_error("Unable to initialise S2OPC CommonHelper library");
		}

		initStatus = SOPC_ClientConfigHelper_Initialize();
		if (initStatus != SOPC_STATUS_OK)
		{
			Logger::getLogger()->fatal("Unable to initialise S2OPC ClientHelper library");
			throw runtime_error("Unable to initialise S2OPC ClientHelper library");
		}

		Logger::getLogger()->debug("S2OPC Toolkit initialised");
		m_init = true;
	}

	return initStatus;
}

/**
 * Uninitialize the S2OPC Toolkit
 */
void OPCUA::uninitializeS2sdk()
{
	if (m_init)
	{
		SOPC_ClientConfigHelper_Clear();
		SOPC_CommonHelper_Clear();
		m_init = false;
		Logger::getLogger()->debug("S2OPC Toolkit uninitialised");
	}
}

/**
 * Update S2OPC Toolkit message encoding parameters
 *
 * @return		True if parameters successfully updated
 */
bool OPCUA::updateS2parameters()
{
	// The S2OPC Toolkit default value for maximum number of message chunks to accept in an OPC UA service response (receive_max_nb_chunks) is too low (that is, 5).
	// This is too low for OPC UA servers on distant or noisy networks that break messages into many smaller chunks.
	// Update the S2OPC Toolkit encoding constants by doubling 'receive_max_nb_chunks'.
	// This can be done only once for the process before any S2OPC Tookit initialization has taken place.
	SOPC_Common_EncodingConstants encodingConstants = SOPC_Common_GetDefaultEncodingConstants();

	encodingConstants.receive_max_nb_chunks = 2 * SOPC_DEFAULT_RECEIVE_MAX_NB_CHUNKS;

	bool parameterUpdateOK = SOPC_Common_SetEncodingConstants(encodingConstants);

	if (!parameterUpdateOK)
	{
		Logger::getLogger()->warn("updateS2parameters: Unable to change 'receive_max_nb_chunks' from %u to %u",
								  (uint32_t)SOPC_DEFAULT_RECEIVE_MAX_NB_CHUNKS, encodingConstants.receive_max_nb_chunks);
	}

	return parameterUpdateOK;
}

/**
 * Create an S2OPC Toolkit Subscription
 *
 * @return		S2OPC status code
 */
SOPC_ReturnStatus OPCUA::createS2Subscription()
{
	SOPC_ReturnStatus status = SOPC_STATUS_OK;

	OpcUa_CreateSubscriptionRequest *subscriptionRequest = SOPC_CreateSubscriptionRequest_Create(500.0, 10, 3, 1000, true, 0);

	m_subscription = SOPC_ClientHelperNew_CreateSubscription(m_connection, subscriptionRequest, subscriptionCallback, (uintptr_t)NULL);
	if (m_subscription == NULL)
	{
		Logger::getLogger()->error("SOPC_ClientHelperNew_CreateSubscription returned NULL");
		status = SOPC_STATUS_OUT_OF_MEMORY;
	}
	else
	{
		double revisedPublishingInterval = 0.0;
		uint32_t revisedLifetimeCount = 0;
		uint32_t revisedMaxKeepAliveCount = 0;
		status = SOPC_ClientHelperNew_Subscription_GetRevisedParameters(
			m_subscription, &revisedPublishingInterval, &revisedLifetimeCount, &revisedMaxKeepAliveCount);
		if (SOPC_STATUS_OK == status)
		{
			Logger::getLogger()->info("Revised Subscription parameters: publishingInterval: %.1f ms, lifetimeCount: %u cycles, keepAliveCount: %u cycles",
									  revisedPublishingInterval, revisedLifetimeCount, revisedMaxKeepAliveCount);
		}
		else
		{
			Logger::getLogger()->error("Error %d: Failed to retrieve subscription revised parameters", (int)status);
		}
	}

	return status;
}

/**
 * Delete an S2OPC Toolkit Subscription
 *
 * @return		S2OPC status code
 */
SOPC_ReturnStatus OPCUA::deleteS2Subscription()
{
	SOPC_ReturnStatus status = SOPC_STATUS_OK;

	if (m_subscription != NULL)
	{
		status = SOPC_ClientHelperNew_DeleteSubscription(&m_subscription);
		m_subscription = NULL;
	}

	return status;
}

/**
 * Create Monitored Items and add them to the S2OPC Subscription
 *
 * @param nodeIds		Array of pointers to NodeId strings
 * @param numNodeIds	Number of NodeIds to add
 * @param logRevisions	If true, log revised sampling interval and queue size
 * @param numErrors		Number of NodeIds in error that cannot become MonitoredItems (returned)
 * @return				S2OPC status code
 */
SOPC_ReturnStatus OPCUA::createS2MonitoredItems(char *const *nodeIds, const size_t numNodeIds, bool logRevisions, size_t *numErrors)
{
	SOPC_ReturnStatus status = SOPC_STATUS_OK;

	OpcUa_CreateMonitoredItemsRequest *monitoredItemsRequest = SOPC_CreateMonitoredItemsRequest_CreateDefaultFromStrings(0, numNodeIds, nodeIds, OpcUa_TimestampsToReturn_Source);
	OpcUa_CreateMonitoredItemsResponse monitoredItemsResponse;
	OpcUa_CreateMonitoredItemsResponse_Initialize(&monitoredItemsResponse);

	for (int32_t j = 0; j < monitoredItemsRequest->NoOfItemsToCreate; j++)
	{
		SOPC_ExtensionObject *dataChangeFilter = m_dcfEnabled ? SOPC_MonitoredItem_DataChangeFilter(m_dcfTriggerType, m_dcfDeadbandType, m_dcfDeadbandValue) : NULL;

		status = SOPC_CreateMonitoredItemsRequest_SetMonitoredItemParams(
			monitoredItemsRequest,
			j,
			OpcUa_MonitoringMode_Reporting,
			0,
			0.0,										// samplingInterval: 0.0 means best possible rate supported by the server
			dataChangeFilter,
			std::numeric_limits<uint32_t>::max(),		// queueSize: MAXUINT32 means largest queue size supported by the server
			1);
		if (SOPC_STATUS_OK != status)
		{
			Logger::getLogger()->error("Error %d: SOPC_CreateMonitoredItemsRequest_SetMonitoredItemParams", (int)status);
		}
	}

	const uintptr_t *nodeIdsCtxArray = (const uintptr_t *)nodeIds;
	status = SOPC_ClientHelperNew_Subscription_CreateMonitoredItems(m_subscription, monitoredItemsRequest, nodeIdsCtxArray,
																	&monitoredItemsResponse);
	if (SOPC_STATUS_OK != status)
	{
		Logger::getLogger()->error("Error %d: Failed to create %u Monitored Items", (int)status, numNodeIds);
	}
	else
	{
		bool oneSucceeded = false;
		for (int32_t i = 0; i < monitoredItemsResponse.NoOfResults; i++)
		{
			if (SOPC_IsGoodStatus(monitoredItemsResponse.Results[i].StatusCode))
			{
				oneSucceeded = true;
				if (logRevisions)
				{
					// The OPC UA server must respond with its revised sampling interval and queue size.
					// See OPC UA Specification, Part 4, Section 7.21: MonitoringParameters
					// https://reference.opcfoundation.org/Core/Part4/v105/docs/7.21
					Logger::getLogger()->info("MonitoredItem RevisedSamplingInterval: %.1f ms RevisedQueueSize: %u",
											  monitoredItemsResponse.Results[i].RevisedSamplingInterval,
											  monitoredItemsResponse.Results[i].RevisedQueueSize);
					logRevisions = false;
				}
				Logger::getLogger()->debug("MonitoredItem %d for Node %s Id %u", i, m_nodeIds[i], monitoredItemsResponse.Results[i].MonitoredItemId);
			}
			else
			{
				// Execution will land here if a Data Change Filter with Deadband is configured for a non-numeric type
				// or if the Deadband Type is not supported by the OPC UA server.
				// Possible Status Codes are BadMonitoredItemFilterUnsupported (0x80440000) and BadFilterNotAllowed (0x80450000).
				Logger::getLogger()->error("Error 0x%08X: Creation of MonitoredItem for Node %s failed",
										   monitoredItemsResponse.Results[i].StatusCode, m_nodeIds[i]);
				(*numErrors)++;
			}
		}
		if (!oneSucceeded)
		{
			status = SOPC_STATUS_WOULD_BLOCK;
		}
	}

	return status;
}

/**
 * Get the full path of the Node by concatenating all parents up to (but not including) the Objects Folder
 *
 * @param node			The current node to inspect
 * @param path			Full Path to the current node
 */
void OPCUA::getNodeFullPath(const std::string &nodeId, std::string &path)
{
	static std::string pathDelimiter("/");

	SOPC_NodeId nodeId_ObjectsFolder = {
		.IdentifierType = SOPC_IdentifierType_Numeric,
		.Namespace = 0,
		nodeId_ObjectsFolder.Data.Numeric = OpcUaId_ObjectsFolder};

	SOPC_ReturnStatus status = SOPC_STATUS_OK;
	OpcUa_BrowseResponse *browseResponse = NULL;
	OpcUa_BrowseRequest *browseRequest = SOPC_BrowseRequest_Create(1, 0, NULL);
	if (NULL != browseRequest)
	{
		// OpcUa_BrowseDirection_Inverse is in the direction of the parent
		status = SOPC_BrowseRequest_SetBrowseDescriptionFromStrings(
			browseRequest, 0, nodeId.c_str(), OpcUa_BrowseDirection_Inverse, NULL, true, OpcUa_NodeClass_Object,
			(OpcUa_BrowseResultMask)(OpcUa_BrowseResultMask_NodeClass |
									 OpcUa_BrowseResultMask_ReferenceTypeId |
									 OpcUa_BrowseResultMask_BrowseName |
									 OpcUa_BrowseResultMask_DisplayName));
	}
	else
	{
		status = SOPC_STATUS_OUT_OF_MEMORY;
	}

	if (SOPC_STATUS_OK == status)
	{
		status = SOPC_ClientHelperNew_ServiceSync(m_connection, (void *)browseRequest, (void **)&browseResponse);
	}
	else
	{
		Logger::getLogger()->error("Parent Browse returned error %d for Node '%s'", (int)status, nodeId.c_str());
		return;
	}

	bool foundParent = false;

	if ((SOPC_STATUS_OK == status) && SOPC_IsGoodStatus(browseResponse->ResponseHeader.ServiceResult) && 1 == browseResponse->NoOfResults)
	{
		Logger::getLogger()->debug("Parent Browse of '%s' returned %d references",
								   nodeId.c_str(), browseResponse->Results[0].NoOfReferences);

		for (int32_t i = 0; i < browseResponse->Results[0].NoOfReferences; i++)
		{
			OpcUa_ReferenceDescription *reference = &browseResponse->Results[0].References[i];
			const char *nodeIdString = SOPC_NodeId_ToCString(&reference->NodeId.NodeId);
			const char *referenceTypeIdString = SOPC_NodeId_ToCString(&reference->ReferenceTypeId);
			const char *browseNameString = SOPC_String_GetRawCString(&reference->BrowseName.Name);

			Logger::getLogger()->debug("Ref #%d: NodeId '%s', DisplayName '%s', NodeClass '%s', ReferenceTypeId '%s'",
									   i, nodeIdString,
									   SOPC_String_GetRawCString(&reference->DisplayName.defaultText),
									   nodeClassStr(reference->NodeClass).c_str(),
									   referenceTypeIdString);

			// Stop building the full path when the referenced parent is the top-level Objects folder
			int32_t comparison = 0;
			status = SOPC_NodeId_Compare(&reference->NodeId.NodeId, &nodeId_ObjectsFolder, &comparison);
			if (!foundParent && (SOPC_STATUS_OK == status) && (comparison != 0) && IsValidParentReferenceId(&reference->ReferenceTypeId))
			{
				getNodeFullPath(nodeIdString, path);
				path = path.append(pathDelimiter).append(browseNameString);
				foundParent = true;
			}
			SOPC_Free((void *)nodeIdString);
			SOPC_Free((void *)referenceTypeIdString);
		}
	}
	else
	{
		Logger::getLogger()->error("Error %d Service Result 0x%08X browsing Parent of %s",
								   (int)status, browseResponse ? browseResponse->ResponseHeader.ServiceResult : 0, nodeId.c_str());
	}
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
	Logger *logger = Logger::getLogger();

	try
	{
		int stat = 0;
		int n_subscriptions = 0;
		OPCUASecurity security;

		logger->debug("Calling OPCUA::start");
		m_stopped.store(false);
		m_connected.store(false);

		// Create the directory tree for the S2OPC PKI
		std::string instanceRoot = getDataDir() + "/tmp/s2opcua/" + m_instanceName;
		if (createDirectories(m_instanceName, logger))
		{
			logger->error("Unable to create directory %s", instanceRoot.c_str());
			return;
		}
		else
		{
			logger->info("Directory created: %s", instanceRoot.c_str());
		}

		initializeS2sdk(NULL);

		bool configOK = true; // if true, plugin configuration is valid

		security.security_mode = m_secMode;
		if (m_secMode == OpcUa_MessageSecurityMode_None)
		{
			security.security_policy = SOPC_SecurityPolicy_None_URI;
		}
		else
		{
			security.security_policy = (char *)m_secPolicy.c_str();
		}
		logger->debug("Requesting Security Mode '%s', Security Policy '%s'", securityMode(security.security_mode).c_str(), security.security_policy);

		// Copy the configuration authPolicy into a string allocated by the S2OPC Toolkit.
		// If startup is normal, the S2OPC Toolkit will allocate a different string so this will make freeing the string consistent.
		security.userPolicyId = (char *)SOPC_Malloc(1 + m_authPolicy.length());
		strncpy(security.userPolicyId, m_authPolicy.c_str(), m_authPolicy.length());
		security.userPolicyId[m_authPolicy.length()] = '\0';

		string certstore = getDataDir() + string("/etc/certs/");

		// Check for Certificate Authority (CA) certificate.
		// If found, it must be copied to issuers/certs in the PKI.
		if (m_certAuth.length())
		{
			string cacert = certstore + m_certAuth + ".der";
			if (access(cacert.c_str(), R_OK))
			{
				logger->error("Unable to access CA Certificate %s", cacert.c_str());
				configOK = false;
			}
			else
			{
				logger->info("Using CA Certificate %s", cacert.c_str());
				std::string destCaCertificate = instanceRoot + "/pki/issuers/certs/" + m_certAuth + ".der";
				remove(destCaCertificate.c_str());
				if (stat = copyFile(destCaCertificate.c_str(), cacert.c_str()))
				{
					logger->error("CA Certificate Copy Status %d (from: %s to: %s)", stat, cacert.c_str(), destCaCertificate.c_str());
				}
			}
		}
		else
		{
			logger->warn("No CA Certificate has been configured");
		}

		// Check for Certificate Revocation List (CRL) certificate.
		// If found, it must be copied to issuers/crl in the PKI.
		if (m_caCrl.length())
		{
			string crl = certstore + m_caCrl + ".der";
			if (access(crl.c_str(), R_OK))
			{
				logger->error("Unable to access CRL Certificate %s", crl.c_str());
				configOK = false;
			}
			else
			{
				logger->info("Using CRL Certificate %s", crl.c_str());
				std::string destCrlCertificate = instanceRoot + "/pki/issuers/crl/" + m_caCrl + ".der";
				remove(destCrlCertificate.c_str());
				if (stat = copyFile(destCrlCertificate.c_str(), crl.c_str()))
				{
					logger->error("CRL Certificate Copy Status %d (from: %s to: %s)", stat, crl.c_str(), destCrlCertificate.c_str());
				}
			}
		}
		else
		{
			logger->warn("No Certificate Revocation List has been configured");
		}

		std::string certClient;
		std::string certServer;
		std::string keyClient;

		// Check for OPC UA Server certificate.
		// If found, it must be copied to trusted/certs in the PKI.
		if (m_serverPublic.length())
		{
			certServer = certstore + m_serverPublic + ".der";
			if (access(certServer.c_str(), R_OK))
			{
				logger->error("Unable to access Server Certificate %s", certServer.c_str());
				configOK = false;
			}
			else
			{
				logger->info("Using Server Certificate %s", certServer.c_str());
				std::string destServerCertificate = instanceRoot + "/pki/trusted/certs/" + m_serverPublic + ".der";
				remove(destServerCertificate.c_str());
				if (stat = copyFile(destServerCertificate.c_str(), certServer.c_str()))
				{
					logger->error("Server Certificate Copy Status %d (from: %s to: %s)", certServer.c_str(), destServerCertificate.c_str());
				}
			}
		}
		else
		{
			logger->warn("No Server Certificate has been configured");
		}

		// Check for Client public certificate.
		if (m_clientPublic.length())
		{
			certClient = certstore + m_clientPublic + ".der";
			if (access(certClient.c_str(), R_OK))
			{
				logger->error("Unable to access Client Certificate %s", certClient.c_str());
				configOK = false;
			}
			else
			{
				logger->info("Using Client Certificate %s", certClient.c_str());
			}
		}
		else
		{
			logger->warn("No Client Certificate has been configured");
		}

		// Check for Client private key.
		if (m_clientPrivate.length())
		{
			keyClient = certstore + "pem/" + m_clientPrivate + ".pem";
			if (access(keyClient.c_str(), R_OK) != F_OK)
			{
				// If not in pem subdirectory try without subdirectory
				keyClient = certstore + m_clientPrivate + ".pem";
				if (access(keyClient.c_str(), R_OK) != F_OK)
				{
					logger->error("Unable to access Client Key %s", keyClient.c_str());
					configOK = false;
				}
				else
				{
					logger->info("Using Client Key %s", keyClient.c_str());
				}
			}
			else
			{
				logger->info("Using Client Key %s", keyClient.c_str());
			}
		}
		else
		{
			logger->warn("No Client Key has been configured");
		}

		// GetEndPoints is the first method call that attempts to connect to the OPC UA server.
		// If this does not succeed, start the connection retry thread and exit.
		OpcUa_GetEndpointsResponse *endpoints = GetEndPoints(m_url.c_str());
		if (endpoints == NULL)
		{
			Logger::getLogger()->error("Unable to read OPC UA server endpoints from %s", m_url.c_str());
			setRetryThread(true);
			return;
		}

		// Check for a matching endpoint
		bool matched = false;
		if (endpoints && endpoints->Endpoints)
		{
			logger->debug("Endpoint matching starting....");
			bool matchedMode = false;
			bool matchedPolicyURL = false;
			bool matchedPolicyId = false;
			for (int32_t i = 0; i < endpoints->NoOfEndpoints && matched == false; i++)
			{
				if (endpoints->Endpoints[i].SecurityMode != m_secMode)
				{
					logger->debug("Endpoint %d: security mode does not match %s", i, securityMode(m_secMode).c_str());
					continue;
				}
				else
				{
					logger->debug("Endpoint %d matches on security mode %s", i, securityMode(m_secMode).c_str());
					matchedMode = true;
				}
				if (endpoints->Endpoints[i].SecurityPolicyUri.Length &&
					strcmp(SOPC_String_GetRawCString(&endpoints->Endpoints[i].SecurityPolicyUri), security.security_policy))
				{
					logger->debug("Endpoint %d: security policy mismatch %s != %s", i,
								  SOPC_String_GetRawCString(&endpoints->Endpoints[i].SecurityPolicyUri), security.security_policy);
					continue;
				}
				else
				{
					logger->debug("Endpoint %d matches on security policy %s", i, security.security_policy);
					matchedPolicyURL = true;
				}
				logger->debug("Endpoint %d: checking user ID tokens", i);
				if (matchedMode && matchedPolicyURL)
				{
					OpcUa_UserTokenPolicy *userIds = endpoints->Endpoints[i].UserIdentityTokens;
					for (int32_t j = 0; matched == false && j < endpoints->Endpoints[i].NoOfUserIdentityTokens; j++)
					{
						OpcUa_UserTokenType tokenType = PolicyIdToUserTokenType(security.userPolicyId);

						if (userIds[j].TokenType == tokenType &&
							(userIds[j].SecurityPolicyUri.Length > 0) &&
							!strcmp(SOPC_String_GetRawCString(&userIds[j].SecurityPolicyUri), security.security_policy))
						{
							matchedPolicyId = true;
						}
						else if (userIds[j].TokenType == tokenType && tokenType == OpcUa_UserTokenType_Anonymous)
						{
							matchedPolicyId = true;
						}
						else
						{
							matchedPolicyId = false;
						}

						if (matchedPolicyId)
						{
							SOPC_Free((void *)security.userPolicyId);
							security.userPolicyId = SOPC_String_GetCString(&userIds[j].PolicyId); // Policy Id must match the OPC UA server's name for it
							security.tokenType = userIds[j].TokenType;
							logger->debug("Endpoint %d matches on PolicyId '%s' (%s)(%d)", i, security.userPolicyId, SOPC_String_GetRawCString(&userIds[j].SecurityPolicyUri), (int)userIds[j].TokenType);
							matched = true;
						}
						else
						{
							logger->debug("%d: Security Policy mismatch: Endpoint: '%s' UserIdentityToken: '%s' (%s)(%d)",
										  i, security.security_policy, SOPC_String_GetRawCString(&userIds[j].SecurityPolicyUri),
										  SOPC_String_GetRawCString(&userIds[j].PolicyId), (int)userIds[j].TokenType);
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
								  security.userPolicyId);
			}
			else
			{
				logger->info("Matched Endpoint: Security Mode '%s', Security Policy '%s', Authentication policy '%s'",
							 securityMode(security.security_mode).c_str(), security.security_policy, security.userPolicyId);
			}

			OpcUa_GetEndpointsResponse_Clear((OpcUa_GetEndpointsResponse *)endpoints);
		}

		// SOPC Toolkit must be closed or else the GetEndpoints connection will interfere with the next connection
		uninitializeS2sdk();

		if (configOK && matched)
		{
			initializeS2sdk(m_traceFile);

			std::string xmlFileName = getDataDir() + "/tmp/s2opcua/" + m_instanceName + "/s2opcua_configuration.xml";
			if (!writeS2ConfigXML(xmlFileName, security, certClient, keyClient, certServer))
			{
				logger->error("Unable to create configuration file %s", xmlFileName.c_str());
				return;
			}

			size_t nbConfigs = 0;
			SOPC_SecureConnection_Config **scConfigArray = NULL;

			stat = SOPC_ClientConfigHelper_ConfigureFromXML(xmlFileName.c_str(), NULL, &nbConfigs, &scConfigArray);

			if (SOPC_STATUS_OK != stat)
			{
				logger->error("Error %d loading XML config file %s\n", (int)stat, xmlFileName.c_str());
				return;
			}

			SOPC_SecureConnection_Config *readConnCfg = SOPC_ClientConfigHelper_GetConfigFromId("read");
			if (NULL == readConnCfg)
			{
				logger->error("Failed to load configuration id 'read' from XML configuration file");
				return;
			}

			stat = SOPC_ClientConfigHelper_SetUserNamePasswordCallback(&UsernamePasswordCallback);
			if (stat != SOPC_STATUS_OK)
			{
				logger->error("Error %d setting username callback function", (int)stat);
				return;
			}

			stat = SOPC_ClientHelperNew_Connect(readConnCfg, ClientConnectionEvent, &m_connection);
			if ((SOPC_STATUS_OK == stat) && (m_connection != NULL))
			{
				m_connected.store(true);
			}
			else
			{
				logger->error("Error %d connecting to %s", stat, m_url.c_str());
				m_connection = NULL;
				m_subscription = NULL;
			}
		}

		if (m_connected.load())
		{
			logger->info("Successfully connected to OPC UA Server: %s", m_url.c_str());
			subscribe();
			resolveDuplicateBrowseNames();
		}
		else if (configOK)
		{
			logger->warn("Not connected to OPC UA Server: %s", m_url.c_str());
		}
		else
		{
			logger->warn("Not connected to OPC UA Server: %s due to configuration error", m_url.c_str());
		}
	}
	catch (const std::exception &ex)
	{
		logger->error("plugin_start exception: %s", ex.what());
		setRetryThread(true);
	}
}

/**
 * Stop all subscriptions and disconnect from the OPCUA server
 */
void OPCUA::stop()
{
	Logger::getLogger()->debug("Calling OPCUA::stop");
	m_stopped.store(true);
	m_readyForData.store(false);
	time_t tend = time(0);
	setRetryThread(false);
	if (m_connected.load())
	{
		m_connected.store(false);

		if (NULL != m_connection)
		{
			SOPC_ReturnStatus res = SOPC_STATUS_OK;

			// It is not necessary to delete the MonitoredItems before deleting the Subscription.
			// The OPC UA Specification says that the OPC UA Server must delete all MonitoredItems
			// if the Subscription is deleted. See Part 5, Section 5.13.8: Delete Subscriptions.
			// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.8
			if ((res = deleteS2Subscription()) == SOPC_STATUS_OK)
			{
				Logger::getLogger()->info("Subscription deleted");
			}
			else
			{
				Logger::getLogger()->error("Error %d deleting Subscription", (int)res);
			}

			if ((res = SOPC_ClientHelperNew_Disconnect(&m_connection)) == SOPC_STATUS_OK)
			{
				Logger::getLogger()->info("Disconnected from %s", m_url.c_str());
			}
			else
			{
				Logger::getLogger()->error("Error %d disconnecting from %s", (int)res, m_url.c_str());
			}

			m_connection = NULL;
		}
	}

	uninitializeS2sdk();

	// Remove the PKI directory
	std::string instanceRoot = getDataDir() + "/tmp/s2opcua/" + m_instanceName;
	if (0 == access(instanceRoot.c_str(), F_OK))
	{
		if (0 != removeDirectory(instanceRoot.c_str()))
		{
			Logger::getLogger()->error("Unable to remove directory tree %s", instanceRoot.c_str());
		}
	}

	clearData();
	clearConfig();

	m_totalElapsedSeconds += (tend - m_tstart);
	Logger::getLogger()->info("Total Data Values sent: %lu Total Overflows: %lu Data Rate: %.1f values/sec",
		m_numOpcUaValues, m_numOpcUaOverflows, ((double)m_numOpcUaValues)/((double)m_totalElapsedSeconds));
	Logger::getLogger()->debug("OpcUa_BadNothingToDo: %lu Rate: %.1f warnings/sec",
		m_numOpcUaNothingToDo, ((double)m_numOpcUaNothingToDo)/((double)m_totalElapsedSeconds));

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
 * @return				OpcUa_GetEndpointsResponse pointer, or NULL if an error occurred
 */
OpcUa_GetEndpointsResponse *OPCUA::GetEndPoints(const char *endPointUrl)
{
	Logger *logger = Logger::getLogger();
	SOPC_ReturnStatus status = SOPC_STATUS_OK;
	OpcUa_GetEndpointsRequest *getEndpointsRequest = NULL;
	OpcUa_GetEndpointsResponse *getEndpointsResponse = NULL;

	// Temporary connection created here is not secure.
	// OPC UA endpoint discovery creates a connection with Security Mode and Security Policy of None.
	SOPC_SecureConnection_Config *discConnCfg = SOPC_ClientConfigHelper_CreateSecureConnection(
		"discovery", endPointUrl, OpcUa_MessageSecurityMode_None, SOPC_SecurityPolicy_None);
	if (NULL == discConnCfg)
	{
		logger->error("Unable to CreateSecureConnection for endpoint discovery");
		return NULL;
	}

	getEndpointsRequest = SOPC_GetEndpointsRequest_Create(endPointUrl);

	if (getEndpointsRequest)
	{
		status = SOPC_ClientHelperNew_DiscoveryServiceSync(discConnCfg, getEndpointsRequest, (void **)&getEndpointsResponse);

		if ((SOPC_STATUS_OK == status) && SOPC_IsGoodStatus(getEndpointsResponse->ResponseHeader.ServiceResult))
		{
			logger->debug("OPC UA Server has %d endpoints\n", getEndpointsResponse->NoOfEndpoints);

			for (int32_t i = 0; i < getEndpointsResponse->NoOfEndpoints; i++)
			{
				logger->debug("%d - url: %s\n", i, SOPC_String_GetRawCString(&getEndpointsResponse->Endpoints[i].EndpointUrl));
				logger->debug("%d - security level: %d\n", i, getEndpointsResponse->Endpoints[i].SecurityLevel);
				logger->debug("%d - security mode: %s\n", i, securityMode(getEndpointsResponse->Endpoints[i].SecurityMode).c_str());
				logger->debug("%d - security policy Uri: %s\n", i, SOPC_String_GetRawCString(&getEndpointsResponse->Endpoints[i].SecurityPolicyUri));
				logger->debug("%d - transport profile Uri: %s\n", i, SOPC_String_GetRawCString(&getEndpointsResponse->Endpoints[i].TransportProfileUri));

				OpcUa_UserTokenPolicy *userIds = getEndpointsResponse->Endpoints[i].UserIdentityTokens;
				for (int32_t j = 0; j < getEndpointsResponse->Endpoints[i].NoOfUserIdentityTokens; j++)
				{
					logger->debug("%d %d - policy Id: %s\n", i, j, SOPC_String_GetRawCString(&userIds[j].PolicyId));
					logger->debug("%d %d - token type: %d\n", i, j, userIds[j].TokenType);
					logger->debug("%d %d - issued token type: %s\n", i, j, SOPC_String_GetRawCString(&userIds[j].IssuedTokenType));
					logger->debug("%d %d - issuer endpoint Url: %s\n", i, j, SOPC_String_GetRawCString(&userIds[j].IssuerEndpointUrl));
					logger->debug("%d %d - security policy Uri: %s\n", i, j, SOPC_String_GetRawCString(&userIds[j].SecurityPolicyUri));
				}
			}
		}
		else
		{
			logger->error("DiscoveryServiceSync Error %d Service Result 0x%08X", (int)status,
						  getEndpointsResponse ? getEndpointsResponse->ResponseHeader.ServiceResult : 0);
			getEndpointsResponse = NULL;
		}
	}
	else
	{
		logger->error("SOPC_GetEndpointsRequest_Create failed");
		getEndpointsResponse = NULL;
	}

	return getEndpointsResponse;
}

/**
 * Construct a node class for the given nodeID
 *
 * @param connection	The connection to the OPCUA server
 * @param nodeId		The NodeId of the node to read
 */
OPCUA::Node::Node(SOPC_ClientConnection *connection, const string &nodeId) : m_nodeID(nodeId)
{
	m_nodeClass = OpcUa_NodeClass_Unspecified;
	SOPC_ReturnStatus status = SOPC_STATUS_OK;

	OpcUa_ReadRequest *readRequest = SOPC_ReadRequest_Create(2, OpcUa_TimestampsToReturn_Neither);
	if (NULL != readRequest)
	{
		SOPC_ReadRequest_SetReadValueFromStrings(readRequest, 0, nodeId.c_str(), SOPC_AttributeId_BrowseName, NULL);
		SOPC_ReadRequest_SetReadValueFromStrings(readRequest, 1, nodeId.c_str(), SOPC_AttributeId_NodeClass, NULL);
	}
	else
	{
		Logger::getLogger()->error("Node::Node out of memory");
	}

	OpcUa_ReadResponse *readResponse = NULL;
	status = SOPC_ClientHelperNew_ServiceSync(connection, readRequest, (void **)&readResponse);
	if ((SOPC_STATUS_OK == status) && SOPC_IsGoodStatus(readResponse->ResponseHeader.ServiceResult) && (2 == readResponse->NoOfResults))
	{
		// If the passed nodeId is not found in the OPC UA Server's Address Space, the read request will return:
		// -- BrowseName: SOPC_Variant::BuiltInTypeId == SOPC_Null_Id
		// -- NodeClass: OpcUa_NodeClass == OpcUa_NodeClass_Unspecified (as Int32)
		if (readResponse->Results[0].Value.BuiltInTypeId == SOPC_QualifiedName_Id)
		{
			m_browseName.assign(SOPC_String_GetRawCString(&readResponse->Results[0].Value.Value.Qname->Name));
		}
		m_nodeClass = (OpcUa_NodeClass)readResponse->Results[1].Value.Value.Int32;
	}
	else
	{
		Logger::getLogger()->error("Error %d reading NodeId %s Service Result 0x%08X reading Node %s",
								   (int)status, nodeId.c_str(), readResponse->ResponseHeader.ServiceResult, nodeId.c_str());
		OpcUa_ReadRequest_Clear((void *)readRequest);
		OpcUa_ReadResponse_Clear((void *)readResponse);
	}
}

/**
 * Construct a node class for the given nodeID
 *
 * @param nodeId		The NodeId of the node to read
 * @param browseName	Browse Name of the Node
 */
OPCUA::Node::Node(const string &nodeId, const std::string& BrowseName) : m_nodeID(nodeId), m_browseName(BrowseName)
{
	m_nodeClass = OpcUa_NodeClass_Variable;
}

/**
 * Construct an OPCUASecurity object
 */
OPCUA::OPCUASecurity::OPCUASecurity()
{
	security_policy = SOPC_SecurityPolicy_None_URI;
	security_mode = OpcUa_MessageSecurityMode_None;
	tokenType = OpcUa_UserTokenType_Anonymous;
	userPolicyId = NULL;
}

/**
 * Destruct an OPCUASecurity object
 */
OPCUA::OPCUASecurity::~OPCUASecurity()
{
	SOPC_Free(userPolicyId);
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
 * Browse an Object node to find its child Objects.
 * Recurse through all child Objects.
 *
 * @param nodeid		NodeId of the object to browse
 * @param objectNodeIds	Vector of Object node IDs
 */
void OPCUA::browseObjects(const string &nodeid, std::set<string> &objectNodeIds)
{
	SOPC_ReturnStatus status = SOPC_STATUS_OK;
	Node *parentNode = NULL;
	OpcUa_BrowseResponse *browseResponse = NULL;
	size_t objectCountAtStart = objectNodeIds.size();

	Logger::getLogger()->debug("Object Browsing '%s'", nodeid.c_str());

	OpcUa_BrowseRequest *browseRequest = SOPC_BrowseRequest_Create(1, 0, NULL);
	if (NULL != browseRequest)
	{
		status = SOPC_BrowseRequest_SetBrowseDescriptionFromStrings(
			browseRequest, 0, nodeid.c_str(), OpcUa_BrowseDirection_Forward, NULL, true, OpcUa_NodeClass_Object,
			(OpcUa_BrowseResultMask)(OpcUa_BrowseResultMask_NodeClass |
									 OpcUa_BrowseResultMask_BrowseName |
									 OpcUa_BrowseResultMask_DisplayName));
	}
	else
	{
		status = SOPC_STATUS_OUT_OF_MEMORY;
	}

	if (SOPC_STATUS_OK == status)
	{
		status = SOPC_ClientHelperNew_ServiceSync(m_connection, (void *)browseRequest, (void **)&browseResponse);
	}
	else
	{
		Logger::getLogger()->error("Object Browse returned error %d for Node '%s'", (int)status, nodeid.c_str());
		return;
	}

	if ((SOPC_STATUS_OK == status) && SOPC_IsGoodStatus(browseResponse->ResponseHeader.ServiceResult) && 1 == browseResponse->NoOfResults)
	{
		if (browseResponse->NoOfResults == 0)
		{
			Logger::getLogger()->error("Unable to locate the OPC UA Node '%s'", nodeid.c_str());
		}
		else
		{
			Logger::getLogger()->debug("Object Browse returned %d results %d references", browseResponse->NoOfResults, browseResponse->Results[0].NoOfReferences);

			parentNode = new Node(m_connection, nodeid);
			if (parentNode->getNodeClass() == OpcUa_NodeClass_Object)
			{
				m_nodeObjects.insert(parentNode);
				Logger::getLogger()->debug("Parent insert %s; %u items", parentNode->getNodeId().c_str(), m_nodeObjects.size());
			}
			else
			{
				Logger::getLogger()->warn("Failed to read parent node '%s' Node Class: %s", nodeid.c_str(), nodeClassStr(parentNode->getNodeClass()).c_str());
			}

			for (int32_t i = 0; i < browseResponse->Results[0].NoOfReferences; i++)
			{
				OpcUa_ReferenceDescription *reference = &browseResponse->Results[0].References[i];
				const char *nodeIdString = SOPC_NodeId_ToCString(&reference->NodeId.NodeId);
				const char *browseNameString = SOPC_String_GetRawCString(&reference->BrowseName.Name);

				bool processNode = checkFiltering(SOPC_String_GetRawCString(&reference->BrowseName.Name), reference->NodeClass);
				if (!processNode)
				{
					Logger::getLogger()->debug("Skipping Object Node '%s' with BrowseName '%s', because of filtering config",
											   nodeIdString, browseNameString);
					continue;
				}
				Logger::getLogger()->debug("Object Node '%s' with browseName '%s', survived filtering, adding it to the Objects list...",
										   nodeIdString, browseNameString);

				objectNodeIds.emplace(nodeIdString);
				browseObjects(nodeIdString, objectNodeIds);

				Logger::getLogger()->debug("Item #%d: NodeId %s, displayName %s, nodeClass %s",
										   i, nodeIdString,
										   SOPC_String_GetRawCString(&reference->DisplayName.defaultText),
										   nodeClassStr(reference->NodeClass).c_str());

				SOPC_Free((void *)nodeIdString);
			}

			// The BrowseResponse has a Continuation Point (CP). If the CP is non-empty, there are more browse results to read.
			// Continue browsing with BrowseNextRequest/BrowseNextResponse which will return an updated CP.
			// Loop until the updated CP is empty.
			SOPC_ByteString continuationPoint;
			SOPC_ByteString_Initialize(&continuationPoint);
			SOPC_ByteString_Copy(&continuationPoint, &browseResponse->Results[0].ContinuationPoint);

			while (continuationPoint.Length > 0)
			{
				Logger::getLogger()->debug("Next Continuation Point: Address 0x%08X Length: %d",
										   (uintptr_t)continuationPoint.Data, continuationPoint.Length);

				OpcUa_BrowseNextRequest *browseNextRequest = SOPC_BrowseNextRequest_Create(false, 1);
				SOPC_BrowseNextRequest_SetContinuationPoint(browseNextRequest, 0, &continuationPoint);
				OpcUa_BrowseNextResponse *browseNextResponse = NULL;

				status = SOPC_ClientHelperNew_ServiceSync(m_connection, (void *)browseNextRequest, (void **)&browseNextResponse);

				if ((SOPC_STATUS_OK == status) && SOPC_IsGoodStatus(browseNextResponse->ResponseHeader.ServiceResult) && 1 == browseNextResponse->NoOfResults)
				{
					for (int32_t i = 0; i < browseNextResponse->Results[0].NoOfReferences; i++)
					{
						OpcUa_ReferenceDescription *reference = &browseNextResponse->Results[0].References[i];
						const char *nodeIdString = SOPC_NodeId_ToCString(&reference->NodeId.NodeId);
						const char *browseNameString = SOPC_String_GetRawCString(&reference->BrowseName.Name);

						bool processNode = checkFiltering(SOPC_String_GetRawCString(&reference->BrowseName.Name), reference->NodeClass);
						if (!processNode)
						{
							Logger::getLogger()->debug("Skipping Browse Node '%s' with BrowseName '%s', because of filtering config",
													   nodeIdString, browseNameString);
							continue;
						}
						Logger::getLogger()->debug("Browse Node '%s' with browseName '%s', survived filtering, adding it to the Objects list...",
												   nodeIdString, browseNameString);

						objectNodeIds.emplace(nodeIdString);
						browseObjects(nodeIdString, objectNodeIds);

						Logger::getLogger()->debug("Item #%d: NodeId %s, displayName %s, nodeClass %s",
												   i, nodeIdString,
												   SOPC_String_GetRawCString(&reference->DisplayName.defaultText),
												   nodeClassStr(reference->NodeClass).c_str());

						SOPC_Free((void *)nodeIdString);
					}
				}
				else
				{
					Logger::getLogger()->error("Error %d Service Result 0x%08X browsing Variable %s",
											   (int)status, browseNextResponse->ResponseHeader.ServiceResult, nodeid.c_str());
				}

				SOPC_ByteString_Clear(&continuationPoint);
				SOPC_ByteString_Copy(&continuationPoint, &browseNextResponse->Results[0].ContinuationPoint);
			}

			SOPC_ByteString_Clear(&continuationPoint);
		}
	}
	else
	{
		Logger::getLogger()->error("Error %d Service Result 0x%08X browsing Object %s",
								   (int)status, browseResponse ? browseResponse->ResponseHeader.ServiceResult : 0, nodeid.c_str());
	}

	if (browseResponse)
	{
		SOPC_Encodeable_Delete(browseResponse->encodeableType, (void **)&browseResponse);
	}

	Logger::getLogger()->info("Object Browsing of '%s' (%s) completed, %u child Objects found",
							  nodeid.c_str(),
							  parentNode ? parentNode->getBrowseName().c_str() : "no Browse Name",
							  objectNodeIds.size() - objectCountAtStart);
}

/**
 * Browse an Object node to find its Variables.
 *
 * @param nodeid	NodeId of the Object to browse
 * @param variables	Vector of Variable node IDs
 */
void OPCUA::browseVariables(const string &nodeid, vector<string> &variables)
{
	SOPC_ReturnStatus status = SOPC_STATUS_OK;
	Node *parentNode = NULL;
	OpcUa_BrowseResponse *browseResponse = NULL;
	size_t variableCountAtStart = variables.size();

	Logger::getLogger()->debug("Browsing '%s'", nodeid.c_str());

	OpcUa_BrowseRequest *browseRequest = SOPC_BrowseRequest_Create(1, BROWSE_BLOCKSIZE, NULL);
	if (NULL != browseRequest)
	{
		status = SOPC_BrowseRequest_SetBrowseDescriptionFromStrings(
			browseRequest, 0, nodeid.c_str(), OpcUa_BrowseDirection_Forward, NULL, true, OpcUa_NodeClass_Variable,
			(OpcUa_BrowseResultMask)(OpcUa_BrowseResultMask_NodeClass |
									 OpcUa_BrowseResultMask_BrowseName |
									 OpcUa_BrowseResultMask_DisplayName));
	}
	else
	{
		status = SOPC_STATUS_OUT_OF_MEMORY;
	}

	if (SOPC_STATUS_OK == status)
	{
		status = SOPC_ClientHelperNew_ServiceSync(m_connection, (void *)browseRequest, (void **)&browseResponse);
	}
	else
	{
		Logger::getLogger()->error("Browse returned error %d for Node '%s'", (int)status, nodeid.c_str());
		return;
	}

	if ((SOPC_STATUS_OK == status) && SOPC_IsGoodStatus(browseResponse->ResponseHeader.ServiceResult) && (1 == browseResponse->NoOfResults))
	{
		Logger::getLogger()->debug("Browse returned %d results %d references", browseResponse->NoOfResults, browseResponse->Results[0].NoOfReferences);
		Logger::getLogger()->debug("Browse Continuation Point: Address 0x%08X Length: %d",
								   (uintptr_t)browseResponse->Results[0].ContinuationPoint.Data, browseResponse->Results[0].ContinuationPoint.Length);
		SOPC_StatusCode StatusCode;

		parentNode = new Node(m_connection, nodeid);
		if (parentNode->getNodeClass() == OpcUa_NodeClass_Object)
		{
			m_nodeObjects.insert(parentNode);
			Logger::getLogger()->debug("Parent insert %s; %u items", parentNode->getNodeId().c_str(), m_nodeObjects.size());
		}
		else
		{
			Logger::getLogger()->warn("Failed to read parent node '%s' Node Class: %s", nodeid.c_str(), nodeClassStr(parentNode->getNodeClass()).c_str());
		}

		for (int32_t i = 0; i < browseResponse->Results[0].NoOfReferences; i++)
		{
			OpcUa_ReferenceDescription *reference = &browseResponse->Results[0].References[i];
			const char *nodeIdString = SOPC_NodeId_ToCString(&reference->NodeId.NodeId);
			const char *browseNameString = SOPC_String_GetRawCString(&reference->BrowseName.Name);

			// Filtering: Code flow is here since parent node is included, now:
			// If filterScope is SCOPE_OBJECT, then children are included without check, if they have OpcUa_NodeClass_Variable nodeClass.
			// And if filterScope is SCOPE_VARIABLE or SCOPE_OBJECT_VARIABLE, then children are checked against filtering config for inclusion
			if (getFilterEnabled())
			{
				bool processNode = false;
				switch (getFilterScope())
				{
				case OPCUA::NodeFilterScope::SCOPE_OBJECT:
					processNode = true;
					break;
				case OPCUA::NodeFilterScope::SCOPE_VARIABLE:
				case OPCUA::NodeFilterScope::SCOPE_OBJECT_VARIABLE:
					processNode = checkFiltering(browseNameString, reference->NodeClass);
					break;
				default:
					Logger::getLogger()->warn("Code flow shouldn't have reached this statement: NodeId=%s, filterScope=%s",
											  nodeIdString, getFilterScopeStr().c_str());
					processNode = false;
					break;
				}

				if (!processNode)
				{
					Logger::getLogger()->debug("Skipping Browse Node '%s' with browseName '%s', because of filtering config",
											   nodeIdString, browseNameString);
					continue;
				}
				else
				{
					Logger::getLogger()->debug("Browse Node '%s' with browseName '%s', survived filtering",
											   nodeIdString, browseNameString);
				}
			}

			if (m_nodes.find(nodeIdString) == m_nodes.end())
			{
				variables.push_back(nodeIdString);
				Node *node = new Node(nodeIdString, browseNameString);
				m_nodes[nodeIdString] = node;
				Logger::getLogger()->debug("New entry: Subscribe to Node %s, BrowseName(a) %s", nodeIdString, browseNameString);
			}
			else
				Logger::getLogger()->debug("Existing entry: Subscribe to Node %s, BrowseName(b) %s", nodeIdString, browseNameString);

			m_parentNodes.insert(pair<string, Node *>(nodeIdString, parentNode));
			Logger::getLogger()->debug("Parent of %s: %s", nodeIdString, nodeid.c_str());

			Logger::getLogger()->debug("Item #%d: NodeId %s, displayName %s, nodeClass %s",
									   i, nodeIdString,
									   SOPC_String_GetRawCString(&reference->DisplayName.defaultText),
									   nodeClassStr(reference->NodeClass).c_str());

			SOPC_Free((void *)nodeIdString);
		}

		// The BrowseResponse has a Continuation Point (CP). If the CP is non-empty, there are more browse results to read.
		// Continue browsing with BrowseNextRequest/BrowseNextResponse which will return an updated CP.
		// Loop until the updated CP is empty.
		SOPC_ByteString continuationPoint;
		SOPC_ByteString_Initialize(&continuationPoint);
		SOPC_ByteString_Copy(&continuationPoint, &browseResponse->Results[0].ContinuationPoint);

		while (continuationPoint.Length > 0)
		{
			Logger::getLogger()->debug("Next Continuation Point: Address 0x%08X Length: %d",
									   (uintptr_t)continuationPoint.Data, continuationPoint.Length);

			OpcUa_BrowseNextRequest *browseNextRequest = SOPC_BrowseNextRequest_Create(false, 1);
			SOPC_BrowseNextRequest_SetContinuationPoint(browseNextRequest, 0, &continuationPoint);
			OpcUa_BrowseNextResponse *browseNextResponse = NULL;

			status = SOPC_ClientHelperNew_ServiceSync(m_connection, (void *)browseNextRequest, (void **)&browseNextResponse);

			if ((SOPC_STATUS_OK == status) && SOPC_IsGoodStatus(browseNextResponse->ResponseHeader.ServiceResult) && 1 == browseNextResponse->NoOfResults)
			{
				for (int32_t i = 0; i < browseNextResponse->Results[0].NoOfReferences; i++)
				{
					OpcUa_ReferenceDescription *reference = &browseNextResponse->Results[0].References[i];
					const char *nodeIdString = SOPC_NodeId_ToCString(&reference->NodeId.NodeId);
					const char *browseNameString = SOPC_String_GetRawCString(&reference->BrowseName.Name);

					if (getFilterEnabled())
					{
						bool processNode = false;
						switch (getFilterScope())
						{
						case OPCUA::NodeFilterScope::SCOPE_OBJECT:
							processNode = true;
							break;
						case OPCUA::NodeFilterScope::SCOPE_VARIABLE:
						case OPCUA::NodeFilterScope::SCOPE_OBJECT_VARIABLE:
							processNode = checkFiltering(browseNameString, reference->NodeClass);
							break;
						default:
							Logger::getLogger()->warn("Code flow shouldn't have reached this statement: NodeId=%s, filterScope=%s",
													  nodeIdString, getFilterScopeStr().c_str());
							processNode = false;
							break;
						}

						if (!processNode)
						{
							Logger::getLogger()->debug("Skipping Browse Node '%s' with browseName '%s', because of filtering config",
													   nodeIdString, browseNameString);
							continue;
						}
						else
						{
							Logger::getLogger()->debug("Browse Node '%s' with browseName '%s', survived filtering",
													   nodeIdString, browseNameString);
						}
					}

					if (m_nodes.find(nodeIdString) == m_nodes.end())
					{
						variables.push_back(nodeIdString);
						Node *node = new Node(nodeIdString, browseNameString);
						m_nodes[nodeIdString] = node;
						Logger::getLogger()->debug("New entry: Subscribe to Node %s, BrowseName %s", nodeIdString, browseNameString);
					}
					else
					{
						Logger::getLogger()->debug("Existing entry: Subscribe to Node %s, BrowseName %s", nodeIdString, browseNameString);
					}

					m_parentNodes.insert(pair<string, Node *>(nodeIdString, parentNode));
					Logger::getLogger()->debug("Parent of %s: %s", nodeIdString, nodeid.c_str());

					SOPC_Free((void *)nodeIdString);
				}
			}
			else
			{
				Logger::getLogger()->error("Error %d Service Result 0x%08X browsing Variable %s",
										   (int)status, browseNextResponse->ResponseHeader.ServiceResult, nodeid.c_str());
			}

			SOPC_ByteString_Clear(&continuationPoint);
			SOPC_ByteString_Copy(&continuationPoint, &browseNextResponse->Results[0].ContinuationPoint);
		}

		SOPC_ByteString_Clear(&continuationPoint);
	}
	else
	{
		Logger::getLogger()->error("Error %d Service Result 0x%08X browsing Variable %s",
								   (int)status, browseResponse ? browseResponse->ResponseHeader.ServiceResult : 0, nodeid.c_str());
	}

	if (browseResponse)
	{
		SOPC_Encodeable_Delete(browseResponse->encodeableType, (void **)&browseResponse);
	}

	Logger::getLogger()->info("Variable Browsing of '%s' (%s) completed, %u Variables found",
							  nodeid.c_str(),
							  parentNode ? parentNode->getBrowseName().c_str() : "no Browse Name",
							  variables.size() - variableCountAtStart);
}

/**
 * Disconnection callback has been called
 */
void OPCUA::disconnect()
{
	if (m_stopped.load())
		Logger::getLogger()->info("Disconnected from %s", m_url.c_str());
	else
		Logger::getLogger()->warn("Disconnected from %s. Attempting reconnection...", m_url.c_str());

	m_connected.store(false);
	m_readyForData.store(false);
	m_subscription = NULL;
	m_connection = NULL;

	if (!m_stopped.load())
	{
		// This was not a user initiated stop so start the retry thread
		setRetryThread(true);
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
			clearData();
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
 * Return an OPCUA Security Mode as a string
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
		return string("SignAndEncrypt");
	default:
		return string("invalid");
	}
}

/**
 * Return a string representation of a NodeClass
 *
 * @param nodeClass	 Node Class enumeration value
 * @return			 Node Class as a string
 */
string OPCUA::nodeClassStr(OpcUa_NodeClass nodeClass)
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

	// Create a temporary map of Browse Name to a set of pointers to OPCUA::Nodes that have that Name
	std::map<std::string, std::set<OPCUA::Node *>> browseNameMap;

	// Load the browseNameMap with the Browse Names and OPCUA::Node pointers in the 'm_nodes' master list
	for (auto node : m_nodes)
	{
		try
		{
			browseNameMap.at(node.second->getBrowseName()).insert(node.second);
		}
		catch (const std::out_of_range &e)
		{
			std::set<OPCUA::Node *> newSet;
			newSet.insert(node.second);
			browseNameMap.emplace(std::pair<std::string, std::set<OPCUA::Node *>>(node.second->getBrowseName(), newSet));
		}
	}

	// If a Browse Name is exposed by more than one OPCUA::Node,
	// apply the Browse Name disambiguation to all of the OPCUA::Node instances
	for (auto browseNameMapItem : browseNameMap)
	{
		if (browseNameMapItem.second.size() > 1)
		{
			for (OPCUA::Node *opcuaNode : browseNameMapItem.second)
			{
				opcuaNode->duplicateBrowseName();
			}
		}
	}
}

/**
 * Create the XML configuration file required by the S2OPC Toolkit.
 * All file names passed to this method must be full file paths.
 *
 * @param xmlFileName	XML file name
 * @param security		OPCUASecurity object
 * @param clientPublic	Client Public Key file name
 * @param clientPrivate	Client Private Key file name
 * @param serverPublic	Server Public Key file name
 * @return				If true, XML file was created successfully
 */
bool OPCUA::writeS2ConfigXML(const std::string &xmlFileName, const OPCUASecurity &security,
							 const std::string &clientPublic,
							 const std::string &clientPrivate,
							 const std::string &serverPublic)
{
	if (xmlFileName.empty())
	{
		return false;
	}

	// Open a new file for writing. If the file already exists, delete its contents.
	FILE *f = fopen(xmlFileName.c_str(), "w");
	if (f == NULL)
	{
		return false;
	}

	bool SecurityModePolicyNone = (security.security_mode == OpcUa_MessageSecurityMode_None) &&
								  (0 == strncmp(security.security_policy, SOPC_SecurityPolicy_None_URI, strlen(SOPC_SecurityPolicy_None_URI)));

	std::string pkiPath = getDataDir() + "/tmp/s2opcua/" + m_instanceName + "/pki";
	int err = 0;

	fprintf(f, "<?xml version='1.0' encoding='utf-8'?>\n");
	fprintf(f, "<S2OPC xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"s2opc_clientserver_config.xsd\">\n");
	fprintf(f, "  <ClientConfiguration>\n");

	fprintf(f, "    <PreferredLocales>\n");
	fprintf(f, "      <Locale id=\"en-US\"/>\n");
	fprintf(f, "    </PreferredLocales>\n");

	// ApplicationCertificates element is omitted for Security Mode and Security Policy None
	if (!SecurityModePolicyNone)
	{
		fprintf(f, "    <ApplicationCertificates>\n");
		fprintf(f, "      <ClientCertificate path=\"%s\"/>\n", clientPublic.c_str());
		fprintf(f, "      <ClientKey path=\"%s\" encrypted=\"false\"/>\n", clientPrivate.c_str());
		fprintf(f, "      <ClientPublicKeyInfrastructure path=\"%s\"/>\n", pkiPath.c_str());
		fprintf(f, "    </ApplicationCertificates>\n");
	}

	fprintf(f, "    <ApplicationDescription>\n");
	fprintf(f, "      <ApplicationURI uri=\"fledge.south.s2opcua\"/>\n");
	fprintf(f, "      <ProductURI uri=\"fledge.south.s2opcua\"/>\n");
	fprintf(f, "      <ApplicationName text=\"Fledge South S2OPCUA Plugin\" locale=\"en-US\"/>\n");
	fprintf(f, "      <ApplicationType type=\"Client\"/>\n");
	fprintf(f, "    </ApplicationDescription>\n");

	fprintf(f, "    <Connections>\n");

	// Define a Connection called "read" for signing up and reading Monitored Items
	fprintf(f, "      <Connection serverURL=\"%s\" id=\"read\">\n", m_url.c_str());
	if (!SecurityModePolicyNone)
	{
		fprintf(f, "        <ServerCertificate path=\"%s\"/>\n", serverPublic.c_str()); // omitted for Security Mode and Security Policy None
	}
	fprintf(f, "        <SecurityPolicy uri=\"%s\"/>\n", m_secPolicy.c_str());
	fprintf(f, "        <SecurityMode mode=\"%s\"/>\n", securityMode(m_secMode).c_str());
	if (security.tokenType == OpcUa_UserTokenType_UserName)
	{
		fprintf(f, "        <UserPolicy policyId=\"%s\" tokenType=\"username\"/>\n", security.userPolicyId);
	}
	fprintf(f, "      </Connection>\n");

	fprintf(f, "    </Connections>\n");

	fprintf(f, "  </ClientConfiguration>\n");
	fprintf(f, "</S2OPC>");

	fflush(f);
	fclose(f);

	return true;
}
