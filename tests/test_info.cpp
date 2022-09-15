#include <gtest/gtest.h>
#include <plugin_api.h>
#include <string.h>
#include <string>
#include <rapidjson/document.h>

using namespace std;
using namespace rapidjson;

extern "C" {
	PLUGIN_INFORMATION *plugin_info();
};

TEST(S2OPCUA, PluginInfo)
{
	PLUGIN_INFORMATION *info = plugin_info();
	ASSERT_STREQ(info->name, "s2opcua");
	ASSERT_EQ(info->type, PLUGIN_TYPE_SOUTH);
}

TEST(S2OPCUA, PluginInfoConfigParse)
{
	PLUGIN_INFORMATION *info = plugin_info();
	Document doc;
	doc.Parse(info->config);
	ASSERT_EQ(doc.HasParseError(), false);
	ASSERT_EQ(doc.IsObject(), true);
	ASSERT_EQ(doc.HasMember("plugin"), true);
}
