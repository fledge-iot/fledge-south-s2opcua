/*
 * Fledge S2OPC South service plugin
 *
 * Selection of the UserTokenPolicy and parsing of the server certificate.
 *
 * Released under the Apache 2.0 Licence
 */
#include <security_select.h>
#include <algorithm>

/**
 * Determine whether a Security Policy URI is supported by the S2OPC Toolkit
 * for the protection of a UserIdentityToken
 *
 * @param policyUri	Security Policy URI
 * @return			True if the Security Policy is supported
 */
bool IsSupportedSecurityPolicyUri(const std::string &policyUri)
{
	static const char *supported[] = {
		SECURITY_POLICY_NONE_URI,
		SECURITY_POLICY_BASIC256_URI,
		SECURITY_POLICY_BASIC256SHA256_URI,
		SECURITY_POLICY_AES128SHA256RSAOAEP_URI,
		SECURITY_POLICY_AES256SHA256RSAPSS_URI
	};

	for (const char *uri : supported)
	{
		if (policyUri == uri)
		{
			return true;
		}
	}
	return false;
}

/**
 * Return the Security Policy that protects a UserIdentityToken.
 *
 * OPC UA Part 4, 7.41: if the UserTokenPolicy SecurityPolicyUri is null or empty, the SecurityPolicy
 * of the Endpoint is used. Otherwise the token is protected with its own SecurityPolicy,
 * which may differ from the Endpoint's.
 *
 * @param token				UserTokenPolicy offered by the Endpoint
 * @param endpointPolicyUri	Security Policy of the Endpoint
 * @return					Effective Security Policy URI
 */
std::string EffectiveUserTokenPolicyUri(const UserTokenPolicyInfo &token, const std::string &endpointPolicyUri)
{
	return token.securityPolicyUri.empty() ? endpointPolicyUri : token.securityPolicyUri;
}

/**
 * Select the UserTokenPolicy to use from the tokens offered by one Endpoint.
 *
 * Only tokens of the requested type are considered. For UserName tokens, a token is usable if
 * the S2OPC Toolkit supports its effective Security Policy and the password is not sent in clear text,
 * i.e. a token protected with Security Policy None is only accepted on a SignAndEncrypt channel.
 * Among usable UserName tokens, the first one whose effective Security Policy equals the Endpoint's
 * is preferred. Only if there is none, the first usable token with another Security Policy is selected.
 *
 * @param tokens				UserTokenPolicies offered by the Endpoint, in server order
 * @param requestedTokenType	UserTokenType configured for the plugin
 * @param endpointPolicyUri		Security Policy of the Endpoint
 * @param signAndEncrypt		True if the Secure Channel Security Mode is SignAndEncrypt
 * @return						The selection, with index -1 if no token is usable
 */
UserTokenSelection SelectUserToken(const std::vector<UserTokenPolicyInfo> &tokens,
								   int requestedTokenType,
								   const std::string &endpointPolicyUri,
								   bool signAndEncrypt)
{
	UserTokenSelection selection;
	int fallback = -1;
	std::string fallbackPolicy;

	for (size_t i = 0; i < tokens.size(); i++)
	{
		const UserTokenPolicyInfo &token = tokens[i];
		if (token.tokenType != requestedTokenType)
		{
			continue;
		}

		std::string policy = EffectiveUserTokenPolicyUri(token, endpointPolicyUri);

		if (requestedTokenType != USER_TOKEN_TYPE_USERNAME)
		{
			// Anonymous tokens carry no secret: the first token of the requested type is used
			selection.index = (int)i;
			selection.effectivePolicyUri = policy;
			selection.exactPolicyMatch = (policy == endpointPolicyUri);
			return selection;
		}

		if (!IsSupportedSecurityPolicyUri(policy))
		{
			selection.rejectedUnsupported = true;
			continue;
		}

		// A UserNameIdentityToken protected with Security Policy None is not encrypted.
		// Only accept it if the Secure Channel itself encrypts all messages.
		if (policy == SECURITY_POLICY_NONE_URI && !signAndEncrypt)
		{
			selection.rejectedClearText = true;
			continue;
		}

		if (policy == endpointPolicyUri)
		{
			selection.index = (int)i;
			selection.effectivePolicyUri = policy;
			selection.exactPolicyMatch = true;
			return selection;
		}

		if (fallback < 0)
		{
			fallback = (int)i;
			fallbackPolicy = policy;
		}
	}

	if (fallback >= 0)
	{
		selection.index = fallback;
		selection.effectivePolicyUri = fallbackPolicy;
		selection.exactPolicyMatch = false;
	}
	return selection;
}

/**
 * Return the total length of the first DER encoded SEQUENCE in a buffer.
 *
 * A server certificate followed by its certificate chain (OPC UA Part 6, 6.2.3) is detected
 * by this length being less than the length of the buffer.
 *
 * @param data		Buffer holding DER data
 * @param length	Length of the buffer
 * @return			Length of the first SEQUENCE including its header, or zero if the data is not valid DER
 */
size_t DerSequenceLength(const uint8_t *data, size_t length)
{
	if (data == NULL || length < 2 || data[0] != 0x30)
	{
		return 0;
	}

	size_t headerLength = 2;
	size_t contentLength = 0;
	if (data[1] < 0x80)
	{
		contentLength = data[1];
	}
	else
	{
		size_t numLengthBytes = data[1] & 0x7F;
		if (numLengthBytes == 0 || numLengthBytes > 4 || length < 2 + numLengthBytes)
		{
			return 0;
		}
		for (size_t i = 0; i < numLengthBytes; i++)
		{
			contentLength = (contentLength << 8) | data[2 + i];
		}
		headerLength += numLengthBytes;
	}

	if (contentLength > length - headerLength)
	{
		return 0;
	}
	return headerLength + contentLength;
}

/**
 * Check the certificate the server publishes in its EndpointDescription.
 *
 * OPC UA Part 6, 6.2.3 allows a server to send its certificate followed by its certificate chain,
 * which the S2OPC Toolkit does not support (S2OPC issue #1448). The S2OPC Toolkit also compares the
 * server certificate byte for byte with the configured Server Public Certificate.
 *
 * @param data			Certificate data from the EndpointDescription
 * @param length		Length of the certificate data
 * @param configured	Content of the configured Server Public Certificate (DER), empty if none
 * @return				The result of the check
 */
ServerCertificateCheck CheckServerCertificateData(const uint8_t *data, size_t length,
												  const std::vector<uint8_t> &configured)
{
	ServerCertificateCheck check;
	if (data == NULL || length == 0)
	{
		check.empty = true;
		return check;
	}

	check.certLength = DerSequenceLength(data, length);
	if (check.certLength == 0)
	{
		return check;
	}
	check.valid = true;
	check.chain = (check.certLength < length);

	if (!configured.empty())
	{
		check.mismatch = (configured.size() != check.certLength ||
						  !std::equal(configured.begin(), configured.end(), data));
	}
	return check;
}
