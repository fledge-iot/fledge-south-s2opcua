#include <gtest/gtest.h>
#include <security_select.h>
#include "test_certificates.h"
#include <string>
#include <vector>

using namespace std;

static const string NONE = SECURITY_POLICY_NONE_URI;
static const string BASIC256 = SECURITY_POLICY_BASIC256_URI;
static const string BASIC256SHA256 = SECURITY_POLICY_BASIC256SHA256_URI;
static const string AES256 = SECURITY_POLICY_AES256SHA256RSAPSS_URI;
static const string UNSUPPORTED = "http://opcfoundation.org/UA/SecurityPolicy#Unknown";

static UserTokenPolicyInfo token(int type, const string &policyId, const string &uri)
{
	UserTokenPolicyInfo t;
	t.tokenType = type;
	t.policyId = policyId;
	t.securityPolicyUri = uri;
	return t;
}

static UserTokenPolicyInfo user(const string &policyId, const string &uri)
{
	return token(USER_TOKEN_TYPE_USERNAME, policyId, uri);
}

// Part 4, 7.41: an empty SecurityPolicyUri means the Endpoint's Security Policy protects the token
TEST(SecuritySelect, EmptyTokenPolicyUsesEndpointPolicy)
{
	vector<UserTokenPolicyInfo> tokens = {user("user", "")};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, 0);
	ASSERT_EQ(s.effectivePolicyUri, BASIC256SHA256);
	ASSERT_TRUE(s.exactPolicyMatch);
}

TEST(SecuritySelect, TokenPolicyEqualToEndpointPolicy)
{
	vector<UserTokenPolicyInfo> tokens = {user("user", BASIC256SHA256)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, false);
	ASSERT_EQ(s.index, 0);
	ASSERT_TRUE(s.exactPolicyMatch);
}

// A token whose policy differs from the Endpoint's is accepted if no exact match is offered
TEST(SecuritySelect, TokenPolicyDiffersFromEndpointPolicy)
{
	vector<UserTokenPolicyInfo> tokens = {user("user_basic256", BASIC256)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, 0);
	ASSERT_EQ(s.effectivePolicyUri, BASIC256);
	ASSERT_FALSE(s.exactPolicyMatch);
}

// Review case: a Basic256 token listed before an empty-policy token on a Basic256Sha256 Endpoint
TEST(SecuritySelect, PrefersEndpointPolicyOverEarlierDifferentPolicy)
{
	vector<UserTokenPolicyInfo> tokens = {user("user_basic256", BASIC256), user("user", "")};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, 1);
	ASSERT_EQ(s.effectivePolicyUri, BASIC256SHA256);
	ASSERT_TRUE(s.exactPolicyMatch);
}

TEST(SecuritySelect, PrefersEndpointPolicyOverEarlierNoneToken)
{
	vector<UserTokenPolicyInfo> tokens = {user("user_none", NONE), user("user", BASIC256SHA256)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, 1);
	ASSERT_TRUE(s.exactPolicyMatch);
}

TEST(SecuritySelect, FallbackTakesFirstSupportedPolicy)
{
	vector<UserTokenPolicyInfo> tokens = {user("a", UNSUPPORTED), user("b", AES256), user("c", BASIC256)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, 1);
	ASSERT_EQ(s.effectivePolicyUri, AES256);
	ASSERT_FALSE(s.exactPolicyMatch);
	ASSERT_TRUE(s.rejectedUnsupported);
}

// A None token sends the password in clear text unless the channel encrypts
TEST(SecuritySelect, NoneTokenRejectedOnSign)
{
	vector<UserTokenPolicyInfo> tokens = {user("user", NONE)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, false);
	ASSERT_EQ(s.index, -1);
	ASSERT_TRUE(s.rejectedClearText);
}

TEST(SecuritySelect, NoneTokenAcceptedOnSignAndEncrypt)
{
	vector<UserTokenPolicyInfo> tokens = {user("user", NONE)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, 0);
	ASSERT_EQ(s.effectivePolicyUri, NONE);
	ASSERT_FALSE(s.exactPolicyMatch);
	ASSERT_FALSE(s.rejectedClearText);
}

// Security Mode None: an empty-policy token inherits Security Policy None and is not encrypted
TEST(SecuritySelect, EmptyTokenPolicyOnNoneEndpointRejected)
{
	vector<UserTokenPolicyInfo> tokens = {user("user", "")};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, NONE, false);
	ASSERT_EQ(s.index, -1);
	ASSERT_TRUE(s.rejectedClearText);
}

// Security Mode None: a token with its own policy encrypts the password
TEST(SecuritySelect, EncryptedTokenOnNoneEndpointAccepted)
{
	vector<UserTokenPolicyInfo> tokens = {user("user_none", NONE), user("user", BASIC256SHA256)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, NONE, false);
	ASSERT_EQ(s.index, 1);
	ASSERT_EQ(s.effectivePolicyUri, BASIC256SHA256);
	ASSERT_TRUE(s.rejectedClearText);
}

TEST(SecuritySelect, UnsupportedPolicyRejected)
{
	vector<UserTokenPolicyInfo> tokens = {user("user", UNSUPPORTED)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, -1);
	ASSERT_TRUE(s.rejectedUnsupported);
	ASSERT_FALSE(s.rejectedClearText);
}

TEST(SecuritySelect, OtherTokenTypesIgnored)
{
	vector<UserTokenPolicyInfo> tokens = {token(USER_TOKEN_TYPE_ANONYMOUS, "anon", ""), token(2, "cert", ""), user("user", "")};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, 2);
}

TEST(SecuritySelect, AnonymousTakesFirstAnonymousToken)
{
	vector<UserTokenPolicyInfo> tokens = {user("user", ""), token(USER_TOKEN_TYPE_ANONYMOUS, "anon", UNSUPPORTED)};
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_ANONYMOUS, NONE, false);
	ASSERT_EQ(s.index, 1);
}

TEST(SecuritySelect, NoTokens)
{
	vector<UserTokenPolicyInfo> tokens;
	UserTokenSelection s = SelectUserToken(tokens, USER_TOKEN_TYPE_USERNAME, BASIC256SHA256, true);
	ASSERT_EQ(s.index, -1);
	ASSERT_FALSE(s.rejectedClearText);
	ASSERT_FALSE(s.rejectedUnsupported);
}

TEST(SecuritySelect, SupportedPolicies)
{
	ASSERT_TRUE(IsSupportedSecurityPolicyUri(NONE));
	ASSERT_TRUE(IsSupportedSecurityPolicyUri(BASIC256));
	ASSERT_TRUE(IsSupportedSecurityPolicyUri(BASIC256SHA256));
	ASSERT_TRUE(IsSupportedSecurityPolicyUri(SECURITY_POLICY_AES128SHA256RSAOAEP_URI));
	ASSERT_TRUE(IsSupportedSecurityPolicyUri(AES256));
	ASSERT_FALSE(IsSupportedSecurityPolicyUri(UNSUPPORTED));
	ASSERT_FALSE(IsSupportedSecurityPolicyUri("http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"));
	ASSERT_FALSE(IsSupportedSecurityPolicyUri(""));
}

// Certificate chain detection (OPC UA Part 6, 6.2.3)

// Build a DER SEQUENCE with the given content length, using the long form for lengths >= 128
static vector<uint8_t> derSequence(size_t contentLength, uint8_t fill)
{
	vector<uint8_t> der = {0x30};
	if (contentLength < 0x80)
	{
		der.push_back((uint8_t)contentLength);
	}
	else if (contentLength <= 0xFF)
	{
		der.push_back(0x81);
		der.push_back((uint8_t)contentLength);
	}
	else
	{
		der.push_back(0x82);
		der.push_back((uint8_t)(contentLength >> 8));
		der.push_back((uint8_t)(contentLength & 0xFF));
	}
	der.insert(der.end(), contentLength, fill);
	return der;
}

TEST(CertificateChain, SingleCertificateShortForm)
{
	vector<uint8_t> cert = derSequence(100, 0xAA);
	ASSERT_EQ(DerSequenceLength(cert.data(), cert.size()), cert.size());
}

TEST(CertificateChain, SingleCertificateLongForm)
{
	vector<uint8_t> cert = derSequence(900, 0xAA);
	ASSERT_EQ(cert.size(), 904u);
	ASSERT_EQ(DerSequenceLength(cert.data(), cert.size()), cert.size());
}

TEST(CertificateChain, LongFormOneLengthByte)
{
	vector<uint8_t> cert = derSequence(200, 0xAA);
	ASSERT_EQ(DerSequenceLength(cert.data(), cert.size()), 203u);
}

TEST(CertificateChain, CertificateFollowedByChain)
{
	vector<uint8_t> cert = derSequence(900, 0xAA);
	vector<uint8_t> issuer = derSequence(1000, 0xBB);
	vector<uint8_t> root = derSequence(800, 0xCC);
	vector<uint8_t> chain = cert;
	chain.insert(chain.end(), issuer.begin(), issuer.end());
	chain.insert(chain.end(), root.begin(), root.end());

	size_t length = DerSequenceLength(chain.data(), chain.size());
	ASSERT_EQ(length, cert.size());
	ASSERT_LT(length, chain.size());
}

TEST(CertificateChain, InvalidDer)
{
	vector<uint8_t> notSequence = {0x04, 0x02, 0x00, 0x00};
	ASSERT_EQ(DerSequenceLength(notSequence.data(), notSequence.size()), 0u);
	ASSERT_EQ(DerSequenceLength(NULL, 10), 0u);

	vector<uint8_t> tooShort = {0x30};
	ASSERT_EQ(DerSequenceLength(tooShort.data(), tooShort.size()), 0u);

	vector<uint8_t> indefinite = {0x30, 0x80, 0x00, 0x00};
	ASSERT_EQ(DerSequenceLength(indefinite.data(), indefinite.size()), 0u);

	vector<uint8_t> tooManyLengthBytes = {0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
	ASSERT_EQ(DerSequenceLength(tooManyLengthBytes.data(), tooManyLengthBytes.size()), 0u);

	vector<uint8_t> missingLengthBytes = {0x30, 0x82, 0x03};
	ASSERT_EQ(DerSequenceLength(missingLengthBytes.data(), missingLengthBytes.size()), 0u);
}

TEST(CertificateChain, TruncatedCertificate)
{
	vector<uint8_t> cert = derSequence(900, 0xAA);
	cert.resize(500);
	ASSERT_EQ(DerSequenceLength(cert.data(), cert.size()), 0u);
}

// Server certificate checks with openssl-generated certificates

static vector<uint8_t> concat(const vector<uint8_t> &a, const vector<uint8_t> &b)
{
	vector<uint8_t> r = a;
	r.insert(r.end(), b.begin(), b.end());
	return r;
}

TEST(ServerCertificate, SingleCertificate)
{
	ServerCertificateCheck c = CheckServerCertificateData(SERVER_CERT_DER.data(), SERVER_CERT_DER.size(), SERVER_CERT_DER);
	ASSERT_TRUE(c.valid);
	ASSERT_FALSE(c.empty);
	ASSERT_FALSE(c.chain);
	ASSERT_FALSE(c.mismatch);
	ASSERT_EQ(c.certLength, SERVER_CERT_DER.size());
}

TEST(ServerCertificate, CertificateChain)
{
	vector<uint8_t> chain = concat(SERVER_CERT_DER, CA_CERT_DER);
	ServerCertificateCheck c = CheckServerCertificateData(chain.data(), chain.size(), SERVER_CERT_DER);
	ASSERT_TRUE(c.valid);
	ASSERT_TRUE(c.chain);
	ASSERT_EQ(c.certLength, SERVER_CERT_DER.size());
	// The server certificate at the start of the chain matches the configured certificate
	ASSERT_FALSE(c.mismatch);
}

TEST(ServerCertificate, ChainMismatch)
{
	vector<uint8_t> chain = concat(SERVER_CERT_DER, CA_CERT_DER);
	ServerCertificateCheck c = CheckServerCertificateData(chain.data(), chain.size(), OTHER_CERT_DER);
	ASSERT_TRUE(c.chain);
	ASSERT_TRUE(c.mismatch);
}

TEST(ServerCertificate, Mismatch)
{
	ServerCertificateCheck c = CheckServerCertificateData(SERVER_CERT_DER.data(), SERVER_CERT_DER.size(), OTHER_CERT_DER);
	ASSERT_TRUE(c.valid);
	ASSERT_FALSE(c.chain);
	ASSERT_TRUE(c.mismatch);
}

// The configured certificate is the CA, not the server certificate
TEST(ServerCertificate, MismatchConfiguredChain)
{
	vector<uint8_t> configured = concat(SERVER_CERT_DER, CA_CERT_DER);
	ServerCertificateCheck c = CheckServerCertificateData(SERVER_CERT_DER.data(), SERVER_CERT_DER.size(), configured);
	ASSERT_TRUE(c.mismatch);
}

TEST(ServerCertificate, NoConfiguredCertificate)
{
	ServerCertificateCheck c = CheckServerCertificateData(SERVER_CERT_DER.data(), SERVER_CERT_DER.size(), vector<uint8_t>());
	ASSERT_TRUE(c.valid);
	ASSERT_FALSE(c.mismatch);
}

TEST(ServerCertificate, InvalidDer)
{
	vector<uint8_t> pem = {'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N'};
	ServerCertificateCheck c = CheckServerCertificateData(pem.data(), pem.size(), SERVER_CERT_DER);
	ASSERT_FALSE(c.valid);
	ASSERT_FALSE(c.empty);
	ASSERT_FALSE(c.chain);
	ASSERT_FALSE(c.mismatch);

	vector<uint8_t> truncated(SERVER_CERT_DER.begin(), SERVER_CERT_DER.begin() + SERVER_CERT_DER.size() / 2);
	c = CheckServerCertificateData(truncated.data(), truncated.size(), SERVER_CERT_DER);
	ASSERT_FALSE(c.valid);
}

TEST(ServerCertificate, EmptyInput)
{
	ServerCertificateCheck c = CheckServerCertificateData(NULL, 0, SERVER_CERT_DER);
	ASSERT_TRUE(c.empty);
	ASSERT_FALSE(c.valid);
	ASSERT_FALSE(c.mismatch);

	c = CheckServerCertificateData(SERVER_CERT_DER.data(), 0, SERVER_CERT_DER);
	ASSERT_TRUE(c.empty);
}
