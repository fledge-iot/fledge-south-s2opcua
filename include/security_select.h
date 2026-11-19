#ifndef _SECURITY_SELECT_H
#define _SECURITY_SELECT_H
/*
 * Fledge S2OPC South service plugin
 *
 * Selection of the UserTokenPolicy and parsing of the server certificate.
 * These helpers do not depend on the S2OPC Toolkit so that they can be unit tested.
 *
 * Released under the Apache 2.0 Licence
 */
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Security Policy URIs, OPC UA Part 7
#define SECURITY_POLICY_NONE_URI "http://opcfoundation.org/UA/SecurityPolicy#None"
#define SECURITY_POLICY_BASIC256_URI "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
#define SECURITY_POLICY_BASIC256SHA256_URI "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
#define SECURITY_POLICY_AES128SHA256RSAOAEP_URI "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
#define SECURITY_POLICY_AES256SHA256RSAPSS_URI "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"

// UserTokenType values, OPC UA Part 4, 7.43
const int USER_TOKEN_TYPE_ANONYMOUS = 0;
const int USER_TOKEN_TYPE_USERNAME = 1;

/**
 * A UserTokenPolicy offered by an Endpoint (OPC UA Part 4, 7.41)
 */
struct UserTokenPolicyInfo
{
	int tokenType;					// UserTokenType
	std::string policyId;			// PolicyId
	std::string securityPolicyUri;	// SecurityPolicyUri, empty if null or empty
};

/**
 * Result of the selection of a UserTokenPolicy within one Endpoint
 */
struct UserTokenSelection
{
	int index = -1;					// Index of the selected token, -1 if none
	std::string effectivePolicyUri;	// Security Policy that protects the selected token
	bool exactPolicyMatch = false;	// The effective policy equals the Endpoint's Security Policy
	bool rejectedClearText = false;	// A token was skipped because the password would be sent in clear text
	bool rejectedUnsupported = false; // A token was skipped because its Security Policy is not supported
};

bool IsSupportedSecurityPolicyUri(const std::string &policyUri);

std::string EffectiveUserTokenPolicyUri(const UserTokenPolicyInfo &token, const std::string &endpointPolicyUri);

UserTokenSelection SelectUserToken(const std::vector<UserTokenPolicyInfo> &tokens,
								   int requestedTokenType,
								   const std::string &endpointPolicyUri,
								   bool signAndEncrypt);

size_t DerSequenceLength(const uint8_t *data, size_t length);

/**
 * Result of the check of the certificate the server publishes in its EndpointDescription
 */
struct ServerCertificateCheck
{
	bool empty = false;			// The server published no certificate
	bool valid = false;			// The data starts with a valid DER certificate
	bool chain = false;			// The certificate is followed by a certificate chain
	bool mismatch = false;		// The certificate differs from the configured Server Public Certificate
	size_t certLength = 0;		// Length of the server certificate without the chain
};

ServerCertificateCheck CheckServerCertificateData(const uint8_t *data, size_t length,
												  const std::vector<uint8_t> &configured);

#endif
