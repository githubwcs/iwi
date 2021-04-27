#include <net/if.h>
#include <errno.h>
#include <string.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"
#include "iw.h"
#include "iwl_vendor_cmd.h"

SECTION(iwl);

static struct nla_policy iwl_vendor_policy[NUM_IWL_MVM_VENDOR_ATTR] = {
	[IWL_MVM_VENDOR_ATTR_LOW_LATENCY] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_VIF_ADDR] = { .type = NLA_UNSPEC },
	[IWL_MVM_VENDOR_ATTR_WIPHY_FREQ] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_CHANNEL_WIDTH] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_CENTER_FREQ1] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_CENTER_FREQ2] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_NEIGHBOR_REPORT] = { .type = NLA_NESTED },
};

static int handle_iwl_vendor_dev_tx_power(struct nl80211_state *state,
					  struct nl_msg *msg,
					  int argc, char **argv,
					  enum id_input id)
{
	struct nlattr *limits;

	if (argc != 0 && argc != 3)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_SET_NIC_TXPOWER_LIMIT);

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!limits)
		return -ENOBUFS;

	if (argc == 3) {
		NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24,
			    atoi(argv[0]) * 8);
		NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L,
			    atoi(argv[1]) * 8);
		NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H,
			    atoi(argv[2]) * 8);
	}

	nla_nest_end(msg, limits);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, dev_tx_power, "[2.4 5.2L 5.2H]",
	NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_dev_tx_power, "");

static int handle_iwl_vendor_sar_set_profile(struct nl80211_state *state,
					     struct nl_msg *msg,
					     int argc, char **argv,
					     enum id_input id)
{
	struct nlattr *limits;
	char *end;
	unsigned int profile;

	if (argc != 0 && argc != 2)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_SET_SAR_PROFILE);

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!limits)
		return -ENOBUFS;

	profile = strtoul(argv[0], &end, 10);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE, profile);

	profile = strtoul(argv[1], &end, 10);
	if (*end != '\0')
		return 1;

	NLA_PUT_U8(msg, IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE, profile);

	nla_nest_end(msg, limits);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, sar_set_profile, "[chain_a chain_b]",
	NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_sar_set_profile, "");

static struct nlattr *parse_vendor_reply(struct nl_msg *msg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (void *)nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
	genlmsg_attrlen(gnlh, 0), NULL);
	return tb[NL80211_ATTR_VENDOR_DATA];
}

static int print_profile_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *data = parse_vendor_reply(msg);
	struct nlattr *attr[MAX_IWL_MVM_VENDOR_ATTR + 1];
	int profs, prof_a, prof_b;

	if (!data)
		return NL_SKIP;

	if (nla_parse_nested(attr, MAX_IWL_MVM_VENDOR_ATTR, data, NULL)) {
		printf("Failed to get sar profiles info");
		return NL_SKIP;
	}

	if (!attr[IWL_MVM_VENDOR_ATTR_SAR_ENABLED_PROFILE_NUM] ||
	    !attr[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE] ||
	    !attr[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE]) {
		fprintf(stderr, "SAR missing info\n");
		return NL_SKIP;
	}

	profs = nla_get_u8(attr[IWL_MVM_VENDOR_ATTR_SAR_ENABLED_PROFILE_NUM]);
	prof_a = nla_get_u8(attr[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE]);
	prof_b = nla_get_u8(attr[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE]);

	printf("Number of enabled SAR profiles: %d\n", profs);
	printf("Current profile in use for chain a: %d\n", prof_a);
	printf("Current profile in use for chain_b: %d\n", prof_b);

	return NL_SKIP;
}

static int handle_iwl_vendor_sar_get_profile_info(struct nl80211_state *state,
						  struct nl_msg *msg,
						  int argc, char **argv,
						  enum id_input id)
{
	struct nlattr *limits;
	int num;

	if (argc != 0)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_GET_SAR_PROFILE_INFO);

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!limits)
		return -ENOBUFS;

	nla_nest_end(msg, limits);
	register_handler(print_profile_handler, &num);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, sar_get_profiles_info, "",
	NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_sar_get_profile_info, "");

static int print_geo_profile(struct nlattr *profile_attr, int n_bands, int *prof_num)
{
	struct nlattr *entry[MAX_IWL_MVM_VENDOR_ATTR + 1], *entries;
	char *bands[] = { "2.4", "5.2", "6-7" };
	int profs;

	if (prof_num)
		printf("Profile #%d\n", *prof_num);

	nla_for_each_nested(entries, profile_attr, profs) {
		if (nla_type(entries) > n_bands)
			break;

		if (nla_parse_nested(entry, MAX_IWL_MVM_VENDOR_ATTR,
				     entries, NULL)) {
			printf("Failed to parse SAR geographic profile data\n");
			return -EINVAL;
		}
		if (nla_type(entries) > (int)ARRAY_SIZE(bands)) {
			printf("Too many nested attributes for SAR GEO profile\n");
			return -EINVAL;
		}

		if (!entry[IWL_VENDOR_SAR_GEO_CHAIN_A_OFFSET] ||
		    !entry[IWL_VENDOR_SAR_GEO_CHAIN_B_OFFSET] ||
		    !entry[IWL_VENDOR_SAR_GEO_MAX_TXP]) {
			printf("SAR geographic profile disabled\n");
		} else {
			int chain_a_offset, chain_b_offset, max;

			chain_a_offset = nla_get_u8(entry[IWL_VENDOR_SAR_GEO_CHAIN_A_OFFSET]);
			chain_b_offset = nla_get_u8(entry[IWL_VENDOR_SAR_GEO_CHAIN_B_OFFSET]);
			max = nla_get_u8(entry[IWL_VENDOR_SAR_GEO_MAX_TXP]);

			printf("%sGHz\n\tChain A offset: %d.%03d dBm\n\tChain B offset: %d.%03d dBm\n\tMax tx power: %d.%03d dBm\n",
			       bands[nla_type(entries) - 1],
			       chain_a_offset / 8, 125*(chain_a_offset % 8),
			       chain_b_offset / 8, 125*(chain_b_offset % 8),
			       max / 8, 125 * (max % 8));
		}
	}
	return 0;
}

#define GEO_SAR_NUM_BANDS_V1 2
#define GEO_SAR_NUM_BANDS_V2 3

static int print_geo_profile_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *data = parse_vendor_reply(msg);
	struct nlattr *attr[MAX_IWL_MVM_VENDOR_ATTR + 1];
	int ret;

	if (!data)
		return NL_SKIP;

	if (nla_parse_nested(attr, MAX_IWL_MVM_VENDOR_ATTR, data, NULL)) {
		printf("Failed to get SAR geographic profile info");
		return NL_SKIP;
	}
	if (!attr[IWL_MVM_VENDOR_ATTR_SAR_GEO_PROFILE])
		return NL_SKIP;

	ret = print_geo_profile(attr[IWL_MVM_VENDOR_ATTR_SAR_GEO_PROFILE],
				GEO_SAR_NUM_BANDS_V1, NULL);
	if(ret)
		return ret;

	return NL_SKIP;
}

static int handle_iwl_vendor_sar_get_geo_profile(struct nl80211_state *state,
						 struct nl_msg *msg,
						 int argc, char **argv,
						 enum id_input id)
{
	int num;

	if (argc != 0)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_GET_SAR_GEO_PROFILE);

	register_handler(print_geo_profile_handler, &num);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, sar_get_geo_profile, "",
	NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_sar_get_geo_profile, "");

static int handle_iwl_vendor_set_country(struct nl80211_state *state,
					 struct nl_msg *msg,
					 int argc, char **argv,
					 enum id_input id)
{
	struct nlattr *limits;

	if (argc != 1 || strlen(argv[0]) != 2)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_SET_COUNTRY);

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!limits)
		return -ENOBUFS;

	NLA_PUT_STRING(msg, IWL_MVM_VENDOR_ATTR_COUNTRY, argv[0]);
	nla_nest_end(msg, limits);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, country, "<alpha2>", NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_set_country, "");

static int handle_iwl_vendor_set_rxfilter(struct nl80211_state *state,
					  struct nl_msg *msg,
					  int argc, char **argv,
					  enum id_input id)
{
	struct nlattr *config;
	enum iwl_mvm_vendor_rxfilter_flags flag;
	enum iwl_mvm_vendor_rxfilter_op op;

	if (argc != 2)
		return 1;

	flag = atoi(argv[0]);
	if (flag < 0 || flag > 3)
		return 1;

	if (strcmp(argv[1], "drop") == 0)
		op = IWL_MVM_VENDOR_RXFILTER_OP_DROP;
	else if (strcmp(argv[1], "pass") == 0)
		op = IWL_MVM_VENDOR_RXFILTER_OP_PASS;
	else
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_RXFILTER);

	config = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!config)
		return -ENOBUFS;

	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_RXFILTER, 1 << flag);
	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_RXFILTER_OP, op);
	nla_nest_end(msg, config);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, rxfilter, "<filter> <pass|drop>", NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_set_rxfilter,
	"filter: 0=unicast, 1=broadcast, 2=IPv4 multicast, 3=IPv6 multicast");

static int handle_iwl_vendor_neighbor_request(struct nl80211_state *state,
					      struct nl_msg *msg,
					      int argc, char **argv,
					      enum id_input id)
{
	struct nlattr *req;
	char *ssid = NULL;
	bool lci = false, civic = false;
	int arg_idx = 0;

	if (argc && strncmp(argv[0], "ssid=", 5) == 0) {
		ssid = argv[0] + 5;
		if (strlen(ssid) > 32)
			return -EINVAL;

		arg_idx++;
	}

	if (argc > arg_idx && strcmp(argv[arg_idx], "lci") == 0) {
		lci = true;
		arg_idx++;
	}

	if (argc > arg_idx && strcmp(argv[2], "civic") == 0)
		civic = true;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_NEIGHBOR_REPORT_REQUEST);

	req = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!req)
		return -ENOBUFS;

	if (ssid)
		NLA_PUT(msg, IWL_MVM_VENDOR_ATTR_SSID, strlen(ssid), ssid);

	if (lci)
		NLA_PUT_FLAG(msg, IWL_MVM_VENDOR_ATTR_NEIGHBOR_LCI);

	if (civic)
		NLA_PUT_FLAG(msg, IWL_MVM_VENDOR_ATTR_NEIGHBOR_CIVIC);

	nla_nest_end(msg, req);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, neighbor_request, "[ssid=<SSID>] [lci] [civic]",
	NL80211_CMD_VENDOR, 0, CIB_NETDEV, handle_iwl_vendor_neighbor_request,
	"");

static int iwl_vendor_sha_type(char *arg,
			       enum iwl_vendor_fips_test_vector_sha_type *type)
{
	if (strncmp(arg, "sha1", 4) == 0)
		*type = IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA1;
	else if (strncmp(arg, "sha256", 6) == 0)
		*type = IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA256;
	else if (strncmp(arg, "sha384", 6) == 0)
		*type = IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA384;
	else
		return HANDLER_RET_USAGE;

	return 0;
}

static int iwl_vendor_put_sha_vector(struct nl_msg *msg, int argc, char **argv)
{
	struct nlattr *attr;
	enum iwl_vendor_fips_test_vector_sha_type sha_type;
	int len, ret;
	char buf[128];

	/* SHA vector parameters: type (sha1|sha256|sha384), message */
	if (argc != 2)
		return -EINVAL;

	attr = nla_nest_start(msg, IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_SHA |
			      NLA_F_NESTED);
	if (!attr)
		return -ENOBUFS;

	ret = iwl_vendor_sha_type(argv[0], &sha_type);
	if (ret)
		return ret;

	NLA_PUT_U8(msg, IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE, sha_type);

	len = strlen(argv[1]);
	if (!len || (len % 2) || len / 2 > (int)sizeof(buf))
		return -EINVAL;

	if (!hex2bin(argv[1], buf))
		return -EINVAL;

	NLA_PUT(msg, IWL_VENDOR_FIPS_TEST_VECTOR_SHA_MSG, len / 2, buf);

	nla_nest_end(msg, attr);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}

static int iwl_vendor_put_hmac_kdf_vector(struct nl_msg *msg, int argc,
					  char **argv,
					  enum iwl_mvm_vendor_attr attr_id)
{
	struct nlattr *attr;
	enum iwl_vendor_fips_test_vector_sha_type sha_type;
	int len, ret;
	char buf[256];
	char *end;

	/*
	 * HMAC/KDF vector parameters:
	 * type (sha1|sha256|sha384), result length, key, message
	 */
	if (argc != 4)
		return -EINVAL;

	attr = nla_nest_start(msg, attr_id | NLA_F_NESTED);
	if (!attr)
		return -ENOBUFS;

	ret = iwl_vendor_sha_type(argv[0], &sha_type);
	if (ret)
		return ret;

	NLA_PUT_U8(msg, IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_TYPE, sha_type);

	len = strtoul(argv[1], &end, 10);
	if (*end != '\0' || len % 8)
		return -EINVAL;

	NLA_PUT_U8(msg, IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_RES_LEN, len / 8);

	len = strlen(argv[2]);
	if (!len || (len % 2) || len / 2 > (int)sizeof(buf))
		return -EINVAL;

	if (!hex2bin(argv[2], buf))
		return -EINVAL;

	NLA_PUT(msg, IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_KEY, len / 2, buf);

	len = strlen(argv[3]);
	if (!len || (len % 2) || len / 2 > (int)sizeof(buf))
		return -EINVAL;

	if (!hex2bin(argv[3], buf))
		return -EINVAL;

	NLA_PUT(msg, IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_MSG, len / 2, buf);

	nla_nest_end(msg, attr);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}

static int iwl_vendor_put_hex_attr(struct nl_msg *msg, char *arg, int attr_id)
{
	char buf[256];
	int len;

	len = strlen(arg);
	if (!len)
		return 0;

	if ((len % 2) || len / 2 > (int)sizeof(buf))
		return -EINVAL;

	if (!hex2bin(arg, buf))
		return -EINVAL;

	NLA_PUT(msg, attr_id, len / 2, buf);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

#define KEY_128_LEN_BYTES	16
#define KEY_256_LEN_BYTES	32
#define CCM_NONCE_LEN		13
#define GCM_NONCE_LEN		12

static int iwl_vendor_validate_aes_vector(int argc, char **argv)
{
	char *key;

	/*
	 * AES vector parameters:
	 * <encrypt|decrypt> <key> <payload|ciphertext>
	 */
	if (argc != 3)
		return HANDLER_RET_USAGE;

	key = argv[1];

	if (strlen(key) / 2 != KEY_128_LEN_BYTES &&
	    strlen(key) / 2 != KEY_256_LEN_BYTES)
		return HANDLER_RET_USAGE;

	return 0;
}

static int iwl_vendor_validate_ccm_vector(int argc, char **argv)
{
	char *key, *nonce;

	/*
	 * GCM vector parameters:
	 * <encrypt|decrypt> <key> <nonce> <AAD> <payload|ciphertext>
	 */
	if (argc != 5)
		return HANDLER_RET_USAGE;

	key = argv[1];
	nonce = argv[2];

	if ((strlen(key) / 2) != KEY_128_LEN_BYTES ||
	    (strlen(nonce) / 2) != CCM_NONCE_LEN)
		return HANDLER_RET_USAGE;

	return 0;
}

static int iwl_vendor_validate_gcm_vector(int argc, char **argv)
{
	char *key, *nonce;

	/*
	 * GCM vector parameters:
	 * <encrypt|decrypt> <key> <nonce> <AAD> <payload|ciphertext>
	 */
	if (argc != 5)
		return HANDLER_RET_USAGE;

	key = argv[1];
	nonce = argv[2];

	if (((strlen(key) / 2) != KEY_128_LEN_BYTES &&
	     (strlen(key) / 2) != KEY_256_LEN_BYTES) ||
	    (strlen(nonce) / 2) != GCM_NONCE_LEN)
		return HANDLER_RET_USAGE;

	return 0;
}

static int iwl_vendor_put_hw_vector(struct nl_msg *msg, int argc, char **argv,
				    int attr_id)
{
	struct nlattr *attr;
	int index = 0, ret;

	switch (attr_id) {
	case IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_AES:
		ret = iwl_vendor_validate_aes_vector(argc, argv);
		break;
	case IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_CCM:
		ret = iwl_vendor_validate_ccm_vector(argc, argv);
		break;
	case IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_GCM:
		ret = iwl_vendor_validate_gcm_vector(argc, argv);
		break;
	default:
		return -EINVAL;
	}

	if (ret)
		return ret;

	attr = nla_nest_start(msg, attr_id | NLA_F_NESTED);
	if (!attr)
		return -ENOBUFS;

	if (strncmp(argv[index], "encrypt", 7) == 0)
		NLA_PUT_U32(msg, IWL_VENDOR_FIPS_TEST_VECTOR_HW_FLAGS,
			    IWL_VENDOR_FIPS_TEST_VECTOR_FLAGS_ENCRYPT);
	else if (strncmp(argv[index], "decrypt", 7) != 0)
		return HANDLER_RET_USAGE;

	index++;

	ret = iwl_vendor_put_hex_attr(msg, argv[index++],
				      IWL_VENDOR_FIPS_TEST_VECTOR_HW_KEY);
	if (ret)
		return ret;

	if (attr_id == IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_CCM ||
	    attr_id == IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_GCM) {
		ret = iwl_vendor_put_hex_attr(msg, argv[index++],
					      IWL_VENDOR_FIPS_TEST_VECTOR_HW_NONCE);
		if (ret)
			return ret;

		ret = iwl_vendor_put_hex_attr(msg, argv[index++],
					      IWL_VENDOR_FIPS_TEST_VECTOR_HW_AAD);
		if (ret)
			return ret;
	}

	ret = iwl_vendor_put_hex_attr(msg, argv[index],
				      IWL_VENDOR_FIPS_TEST_VECTOR_HW_PAYLOAD);
	if (ret)
		return ret;

	nla_nest_end(msg, attr);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}

static int print_fips_test_result(struct nl_msg *msg, void *arg)
{
	struct nlattr *data = parse_vendor_reply(msg);
	struct nlattr *attr[MAX_IWL_MVM_VENDOR_ATTR + 1];

	if (!data)
		return NL_SKIP;

	if (nla_parse_nested(attr, MAX_IWL_MVM_VENDOR_ATTR, data, NULL)) {
		printf("Failed to get FIPS test result");
		return NL_SKIP;
	}

	if (!attr[IWL_MVM_VENDOR_ATTR_FIPS_TEST_RESULT]) {
		fprintf(stderr, "FIPS: test failed\n");
		return NL_SKIP;
	}

	iw_hexdump("FIPS RESULT",
		   nla_data(attr[IWL_MVM_VENDOR_ATTR_FIPS_TEST_RESULT]),
		   nla_len(attr[IWL_MVM_VENDOR_ATTR_FIPS_TEST_RESULT]));

	return NL_SKIP;
}

static int handle_iwl_vendor_fips_test(struct nl80211_state *state,
				       struct nl_msg *msg, int argc,
				       char **argv, enum id_input id)
{
	char *type;
	int ret;
	struct nlattr *attr;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_TEST_FIPS);

	if (argc < 2)
		return -EINVAL;

	attr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!attr)
		return -ENOBUFS;

	if (strncmp(argv[0], "type=", 5) != 0)
		return -EINVAL;

	type = argv[0] + 5;
	if (strncmp(type, "sha", 3) == 0)
		ret = iwl_vendor_put_sha_vector(msg, argc - 1, &argv[1]);
	else if (strncmp(type, "hmac", 4) == 0)
		ret = iwl_vendor_put_hmac_kdf_vector(msg, argc - 1, &argv[1],
						     IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HMAC);
	else if (strncmp(type, "kdf", 3) == 0)
		ret = iwl_vendor_put_hmac_kdf_vector(msg, argc - 1, &argv[1],
						     IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_KDF);
	else if (strncmp(type, "aes", 3) == 0)
		ret = iwl_vendor_put_hw_vector(msg, argc - 1, &argv[1],
					       IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_AES);
	else if (strncmp(type, "ccm", 3) == 0)
		ret = iwl_vendor_put_hw_vector(msg, argc - 1, &argv[1],
					       IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_CCM);
	else if (strncmp(type, "gcm", 3) == 0)
		ret = iwl_vendor_put_hw_vector(msg, argc - 1, &argv[1],
					       IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_GCM);
	else
		return -EINVAL;

	if (ret)
		return ret;

	nla_nest_end(msg, attr);

	register_handler(print_fips_test_result, NULL);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(iwl, fips_test, "type=<sha|hmac|kdf> <vector parameters>\n"
	" parameters for SHA test: <sha1|sha256|sha384> <hex encoded message>\n"
	" parameters for HMAC/KDF tests: <sha1|sha256|sha384> <result length in bits>"
	" <hex encoded key> <hex encoded message>\n"
	" parameters for AES test: <encrypt|decrypt> <hex encoded key>"
	" <hex encoded payload/ciphertext>\n"
	" parameters for CCM/GCM tests: <encrypt|decrypt> <hex encoded key>"
	" <hex encoded nonce> <hex encoded AAD> <hex encoded payload/ciphertext>\n",
	NL80211_CMD_VENDOR, 0, CIB_NETDEV, handle_iwl_vendor_fips_test,
	"");

static int handle_iwl_vendor_fmac_connect_params(struct nl80211_state *state,
						 struct nl_msg *msg,
						 int argc, char **argv,
						 enum id_input id)
{
	struct nlattr *params, *bssids;
	int i, arg_idx = 0;
	int bssids_attr;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_FMAC_CONNECT_PARAMS);

	params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!params)
		return -ENOBUFS;

	if (argc < 2)
		goto nest_end;

	if (strncmp(argv[arg_idx], "max_retries", 11) == 0) {
		int max_retries;

		arg_idx++;
		max_retries = atoi(argv[arg_idx]);
		if (max_retries < 0)
			return -EINVAL;

		NLA_PUT_U32(msg,
			    IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_MAX_RETRIES,
			    max_retries);
		arg_idx++;
	}

	if (argc < arg_idx + 2)
		goto nest_end;

	if (strncmp(argv[arg_idx], "whitelist", 9) == 0)
		bssids_attr = IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_WHITELIST;
	else if (strncmp(argv[arg_idx], "blacklist", 9) == 0)
		bssids_attr = IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_BLACKLIST;
	else
		return -EINVAL;

	bssids = nla_nest_start(msg, bssids_attr | NLA_F_NESTED);

	arg_idx++;
	for (i = 0; arg_idx < argc; i++, arg_idx++) {
		unsigned char addr[ETH_ALEN];
		int ret;

		ret = mac_addr_a2n(addr, argv[arg_idx]);
		if (ret < 0)
			return -EINVAL;

		NLA_PUT(msg, i + 1, ETH_ALEN, addr);
	}

	nla_nest_end(msg, bssids);
nest_end:
	nla_nest_end(msg, params);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, fmac_connect, "[max_retries <number of retries>]"
	"[<blacklist|whitelist> <bssid1 bssid2...>]", NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_fmac_connect_params,
	"Set no parameters to clear previous configurations");

static int handle_iwl_vendor_fmac_config(struct nl80211_state *state,
					 struct nl_msg *msg, int argc,
					 char **argv, enum id_input id)
{
	struct nlattr *attr;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_FMAC_CONFIG);

	if (argc != 1)
		return -EINVAL;

	attr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!attr)
		return -ENOBUFS;

	NLA_PUT_STRING(msg, IWL_MVM_VENDOR_ATTR_FMAC_CONFIG_STR, argv[0]);
	nla_nest_end(msg, attr);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, fmac_config, "<key>=<value>",
	NL80211_CMD_VENDOR, 0, CIB_NETDEV, handle_iwl_vendor_fmac_config, "");

static int handle_iwl_vendor_add_pasn_sta(struct nl80211_state *state,
					  struct nl_msg *msg, int argc,
					  char **argv, enum id_input id)
{
	struct nlattr *params;
	unsigned char addr[ETH_ALEN];
	char *cipher_str;
	int ret, cipher;

	if (argc < 3)
		return -EINVAL;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_ADD_PASN_STA);

	params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!params)
		return -ENOBUFS;

	ret = mac_addr_a2n(addr, argv[0]);
	if (ret < 0)
		return -EINVAL;

	NLA_PUT(msg, IWL_MVM_VENDOR_ATTR_ADDR, ETH_ALEN, addr);

	if (strncmp(argv[1], "cipher=", 7) != 0)
		return -EINVAL;

	cipher_str = argv[1] + 7;
	if (strncmp(cipher_str, "ccmp", 4) == 0)
		cipher = WLAN_CIPHER_SUITE_CCMP;
	else if (strncmp(cipher_str, "gcmp256", 7) == 0)
		cipher = WLAN_CIPHER_SUITE_GCMP_256;
	else if (strncmp(cipher_str, "gcmp", 4) == 0)
		cipher = WLAN_CIPHER_SUITE_GCMP;
	else
		return -EINVAL;

	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_STA_CIPHER, cipher);

	if (strncmp(argv[2], "hltk=", 5) != 0)
		return -EINVAL;

	ret = iwl_vendor_put_hex_attr(msg, argv[2] + 5,
				      IWL_MVM_VENDOR_ATTR_STA_HLTK);
	if (ret)
		return ret;

	if (argc == 4 && strncmp(argv[3], "tk=", 3) == 0) {
		ret = iwl_vendor_put_hex_attr(msg, argv[3] + 3,
					      IWL_MVM_VENDOR_ATTR_STA_TK);
		if (ret)
			return ret;
	}

	nla_nest_end(msg, params);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, add_pasn_sta, "<mac address> cipher=<ccmp|gcmp|gcmp256> "
	"hltk=<hex encoded HLTK> [tk=<hex encoded TK>]", NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_add_pasn_sta, "");

static int handle_iwl_vendor_remove_pasn_sta(struct nl80211_state *state,
					     struct nl_msg *msg, int argc,
					     char **argv, enum id_input id)
{
	struct nlattr *params;
	unsigned char addr[ETH_ALEN];
	int ret;

	if (argc != 1)
		return -EINVAL;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_REMOVE_PASN_STA);

	params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!params)
		return -ENOBUFS;

	ret = mac_addr_a2n(addr, argv[0]);
	if (ret < 0)
		return -EINVAL;

	NLA_PUT(msg, IWL_MVM_VENDOR_ATTR_ADDR, ETH_ALEN, addr);

	nla_nest_end(msg, params);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, remove_pasn_sta, "<mac address>", NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_remove_pasn_sta, "");

static int handle_iwl_time_sync_msmt_enable(struct nl80211_state *state,
					    struct nl_msg *msg, int argc,
					    char **argv, enum id_input id)
{
	struct nlattr *params;
	unsigned char addr[ETH_ALEN];
	int protocol;
	int ret;

	if (argc != 2)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_TIME_SYNC_MEASUREMENT_CONFIG);

	params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!params)
		return -ENOBUFS;

	protocol = atoi(argv[0]);

	ret = mac_addr_a2n(addr, argv[1]);
	if (ret < 0)
		return 1;

	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_TIME_SYNC_PROTOCOL_TYPE, protocol);
	NLA_PUT(msg, IWL_MVM_VENDOR_ATTR_ADDR, ETH_ALEN, addr);

	nla_nest_end(msg, params);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, time_sync_msmt_enable, "<protocol TM or FTM> [1|2] <mac address>",
	NL80211_CMD_VENDOR, 0, CIB_NETDEV,
	handle_iwl_time_sync_msmt_enable, "Enable TM [1] or FTM [2] protocol for time synchronization");

static const char * const phy2str[] =
{
	[IWL_MVM_VENDOR_PHY_TYPE_UNSPECIFIED] = "unspecified",
	[IWL_MVM_VENDOR_PHY_TYPE_DSSS] = "DSSS",
	[IWL_MVM_VENDOR_PHY_TYPE_OFDM] = "OFDM",
	[IWL_MVM_VENDOR_PHY_TYPE_HRDSSS] = "HRDSSS",
	[IWL_MVM_VENDOR_PHY_TYPE_ERP] = "ERP",
	[IWL_MVM_VENDOR_PHY_TYPE_HT] = "HT",
	[IWL_MVM_VENDOR_PHY_TYPE_DMG] = "DMG",
	[IWL_MVM_VENDOR_PHY_TYPE_VHT] = "VHT",
	[IWL_MVM_VENDOR_PHY_TYPE_TVHT] = "TVHT",
};

static const char * const vendorwidth2str[] =
{
	[IWL_MVM_VENDOR_CHAN_WIDTH_20] = "20MHz",
	[IWL_MVM_VENDOR_CHAN_WIDTH_40] = "40MHz",
	[IWL_MVM_VENDOR_CHAN_WIDTH_80] = "80MHz",
	[IWL_MVM_VENDOR_CHAN_WIDTH_160] = "160MHz",
	[IWL_MVM_VENDOR_CHAN_WIDTH_80P80] = "80P80MHz",
};

static void parse_neighbor_report(unsigned int id, unsigned int subcmd, struct nlattr *data)
{
	int tmp, err;
	struct nlattr *attrs[NUM_IWL_MVM_VENDOR_ATTR];
	struct nlattr *neighbors;
	static struct nla_policy neighbor_policy[] = {
		[IWL_MVM_VENDOR_NEIGHBOR_BSSID] = { .type = NLA_UNSPEC },
		[IWL_MVM_VENDOR_NEIGHBOR_BSSID_INFO] = { .type = NLA_U32 },
		[IWL_MVM_VENDOR_NEIGHBOR_OPERATING_CLASS] = { .type = NLA_U8 },
		[IWL_MVM_VENDOR_NEIGHBOR_CHANNEL] = { .type = NLA_U8 },
		[IWL_MVM_VENDOR_NEIGHBOR_PHY_TYPE] = { .type = NLA_U8 },
		[IWL_MVM_VENDOR_NEIGHBOR_CHANNEL_WIDTH] = { .type = NLA_U32 },
		[IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_0] = {
			.type = NLA_U32 },
		[IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_1] = {
			.type = NLA_U32 },
		[IWL_MVM_VENDOR_NEIGHBOR_LCI] = { .type = NLA_UNSPEC },
		[IWL_MVM_VENDOR_NEIGHBOR_CIVIC] = { .type = NLA_UNSPEC },
	};

	if (nla_parse_nested(attrs, MAX_IWL_MVM_VENDOR_ATTR, data,
			     iwl_vendor_policy)) {
		printf(" Ignore invalid neighbor report");
		return;
	}

	nla_for_each_nested(neighbors,
			    attrs[IWL_MVM_VENDOR_ATTR_NEIGHBOR_REPORT], tmp) {
		struct nlattr *neighbor[NUM_IWL_MVM_VENDOR_NEIGHBOR_REPORT];
		char addr[3 * ETH_ALEN];

		err = nla_parse_nested(neighbor,
				       MAX_IWL_MVM_VENDOR_NEIGHBOR_REPORT,
				       neighbors, neighbor_policy);
		if (err) {
			printf("Bad neighbor data");
			return;
		}

		mac_addr_n2a(addr,
			     nla_data(neighbor[IWL_MVM_VENDOR_NEIGHBOR_BSSID]));
		printf("\nNeighbor %s\n", addr);
		printf("\tBSS Info: %u\n",
		       nla_get_u32(neighbor[IWL_MVM_VENDOR_NEIGHBOR_BSSID_INFO]));
		printf("\tOperating class: %hhu\n",
		       nla_get_u8(neighbor[IWL_MVM_VENDOR_NEIGHBOR_OPERATING_CLASS]));
		printf("\tChannel: %hhu\n",
		       nla_get_u8(neighbor[IWL_MVM_VENDOR_NEIGHBOR_CHANNEL]));
		printf("\tPHY type: %s\n",
		       phy2str[nla_get_u8(neighbor[IWL_MVM_VENDOR_NEIGHBOR_PHY_TYPE])]);

		if (neighbor[IWL_MVM_VENDOR_NEIGHBOR_CHANNEL_WIDTH]) {
			printf("\tChannel width: %s\n",
			       vendorwidth2str[nla_get_u32(neighbor[IWL_MVM_VENDOR_NEIGHBOR_CHANNEL_WIDTH])]);
			printf("\tCenter freq 0: %u\n",
			       nla_get_u32(neighbor[IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_0]));

			if (neighbor[IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_1])
				printf("\tCenter freq 1: %u\n",
				       nla_get_u32(neighbor[IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_1]));
		}

		if (neighbor[IWL_MVM_VENDOR_NEIGHBOR_LCI])
			iw_hexdump("\tLCI",
				   nla_data(neighbor[IWL_MVM_VENDOR_NEIGHBOR_LCI]),
				   nla_len(neighbor[IWL_MVM_VENDOR_NEIGHBOR_LCI]));

		if (neighbor[IWL_MVM_VENDOR_NEIGHBOR_CIVIC])
			iw_hexdump("\tCIVIC",
				   nla_data(neighbor[IWL_MVM_VENDOR_NEIGHBOR_CIVIC]),
				   nla_len(neighbor[IWL_MVM_VENDOR_NEIGHBOR_CIVIC]));
	}
}

VENDOR_EVENT(INTEL_OUI, IWL_MVM_VENDOR_CMD_NEIGHBOR_REPORT_RESPONSE, parse_neighbor_report);

static int parse_csme_conn_event(struct nl_msg *msg, void *arg)
{
	struct nlattr *data = parse_vendor_reply(msg);
	struct nlattr *attrs[NUM_IWL_MVM_VENDOR_ATTR];
	char macbuf[6*3];

	if (nla_parse_nested(attrs, MAX_IWL_MVM_VENDOR_ATTR, data, iwl_vendor_policy) ) {
		printf("Failed to parse CSME connection info");
		return EINVAL;
	}

	printf("Intel CSME connection info event:");

	if (attrs[IWL_MVM_VENDOR_ATTR_AUTH_MODE])
		printf("\n\tauth mode: %d",
		       nla_get_u8(attrs[IWL_MVM_VENDOR_ATTR_AUTH_MODE]));

	if (attrs[IWL_MVM_VENDOR_ATTR_SSID])
	{
		printf("\n\tSSID: ");
		print_ssid_escaped(nla_len(attrs[IWL_MVM_VENDOR_ATTR_SSID]),
				   nla_data(attrs[IWL_MVM_VENDOR_ATTR_SSID]));
	}

	if (attrs[IWL_MVM_VENDOR_ATTR_STA_CIPHER])
		printf("\n\tucast cipher: %d",
		       nla_get_u8(attrs[IWL_MVM_VENDOR_ATTR_STA_CIPHER]));

	if (attrs[IWL_MVM_VENDOR_ATTR_CHANNEL_NUM])
		printf("\n\tchannel: %d",
		       nla_get_u8(attrs[IWL_MVM_VENDOR_ATTR_CHANNEL_NUM]));

	if (attrs[IWL_MVM_VENDOR_ATTR_ADDR])
	{
		mac_addr_n2a(macbuf, nla_data(attrs[IWL_MVM_VENDOR_ATTR_ADDR]));
		printf("\n\taddress: %s\n", macbuf);
	}

	return NL_SKIP;
}

static int handle_iwl_vendor_get_csme_conn_info(struct nl80211_state *state,
						  struct nl_msg *msg,
						  int argc, char **argv,
						  enum id_input id)
{
	int num;

	if (argc)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_GET_CSME_CONN_INFO);

	register_handler(parse_csme_conn_event, &num);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, get_csme_conn_info, "",
	NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_get_csme_conn_info, "");

static int handle_iwl_vendor_host_disassoc(struct nl80211_state *state,
					  struct nl_msg *msg, int argc,
					  char **argv, enum id_input id)
{
	struct nlattr *params;
	unsigned int type;
	char *type_str;

	if (argc != 1)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_HOST_DISASSOC);

	params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!params)
		return -ENOBUFS;

	type_str = argv[0];
	if (strcmp(type_str, "unknown") == 0)
		type = IWL_VENDOR_DISCONNECT_TYPE_UNKNOWN;
	else if (strcmp(type_str, "temp") == 0)
		type = IWL_VENDOR_DISCONNECT_TYPE_TEMPORARY;
	else if (strcmp(type_str, "long") == 0)
		type = IWL_VENDOR_DISCONNECT_TYPE_LONG;
	else
		return 1;

	NLA_PUT_U8(msg, IWL_MVM_VENDOR_ATTR_HOST_DISASSOC_TYPE, type);
	nla_nest_end(msg, params);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, host_disassoc, "<unknown|temp|long>",
	NL80211_CMD_VENDOR, 0, CIB_NETDEV, handle_iwl_vendor_host_disassoc,
	"Notify on host disassociation");

static int handle_iwl_vendor_host_assoc(struct nl80211_state *state,
					struct nl_msg *msg, int argc,
					char **argv, enum id_input id)
{
	struct nlattr *params;
	int ret, channel, band = 0, cipher, auth, index = 0;
	char *ssid = NULL, *cipher_str = NULL, *auth_str = NULL;
	unsigned char addr[ETH_ALEN];

	if (argc < 4)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_HOST_ASSOC);

	params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!params)
		return -ENOBUFS;

	ssid = argv[index];
	if (strlen(ssid) > 32)
		return 1;

		NLA_PUT(msg, IWL_MVM_VENDOR_ATTR_SSID, strlen(ssid), ssid);

	index++;
	ret = mac_addr_a2n(addr, argv[index]);
	if (ret < 0)
		return 1;

	NLA_PUT(msg, IWL_MVM_VENDOR_ATTR_ADDR, ETH_ALEN, addr);
	index++;

	channel = atoi(argv[index]);
	NLA_PUT_U8(msg, IWL_MVM_VENDOR_ATTR_CHANNEL_NUM, channel);
	index++;

	band = atoi(argv[index]);
	NLA_PUT_U8(msg, IWL_MVM_VENDOR_ATTR_BAND, band);
	index++;

	auth_str = argv[index];
	if (strcmp(auth_str, "open") == 0)
		auth = IWL_VENDOR_AUTH_OPEN;
	else if (strcmp(auth_str, "shared") == 0)
		auth = IWL_VENDOR_AUTH_SHARED;
	else if (strcmp(auth_str, "wpa") == 0)
		auth = IWL_VENDOR_AUTH_WPA;
	else if (strcmp(auth_str, "wpa_psk") == 0)
		auth = IWL_VENDOR_AUTH_WPA_PSK;
	else if (strcmp(auth_str, "rsna") == 0)
		auth = IWL_VENDOR_AUTH_RSNA;
	else if (strcmp(auth_str, "rsna_psk") == 0)
		auth = IWL_VENDOR_AUTH_RSNA_PSK;
	else if (strcmp(auth_str, "sae") == 0)
		auth = IWL_VENDOR_AUTH_SAE;
	else
		return 1;

	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_AUTH_MODE, auth);
	index++;

	if (argc > 5) {
		if (strncmp(argv[index], "cipher=", 7) == 0) {
			cipher_str = argv[index] + 7;
			if (strcmp(cipher_str, "wep") == 0)
				cipher = WLAN_CIPHER_SUITE_WEP40;
			else if (strcmp(cipher_str, "tkip") == 0)
				cipher = WLAN_CIPHER_SUITE_TKIP;
			else if (strcmp(cipher_str, "ccmp") == 0)
				cipher = WLAN_CIPHER_SUITE_CCMP;
			else if (strcmp(cipher_str, "gcmp") == 0)
				cipher = WLAN_CIPHER_SUITE_GCMP;
			else
				return 1;

			NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_STA_CIPHER, cipher);
			index++;
		}
		if (argc > index && strncmp(argv[index], "colloc_info", 11) == 0) {
			index++;
			channel = atoi(argv[index]);
			NLA_PUT_U8(msg, IWL_MVM_VENDOR_ATTR_COLLOC_CHANNEL, channel);
			index++;
			ret = mac_addr_a2n(addr, argv[index]);
			if (ret < 0)
				return 1;

			NLA_PUT(msg, IWL_MVM_VENDOR_ATTR_COLLOC_ADDR, ETH_ALEN, addr);
		}

	}

	nla_nest_end(msg, params);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, host_assoc, "<SSID> <bssid> <channel> <0|1|2> "
	"<open|shared|wpa|wpa_psk|rsna|rsna_psk|sae> "
	"[cipher=<wep|tkip|ccmp|gcmp>] "
	"[colloc_info <channel> <colloc_bssid>]",
	NL80211_CMD_VENDOR, 0, CIB_NETDEV, handle_iwl_vendor_host_assoc,
	"Set host connection parameters");

static int handle_iwl_vendor_get_ownership(struct nl80211_state *state,
					   struct nl_msg *msg, int argc,
					   char **argv, enum id_input id)
{
	if (argc)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_HOST_GET_OWNERSHIP);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, get_ownership, NULL,
	NL80211_CMD_VENDOR, 0, CIB_NETDEV, handle_iwl_vendor_get_ownership,
	"Ask for ownership on the device");

static int handle_iwl_vendor_set_sw_rfkill_state(struct nl80211_state *state,
						 struct nl_msg *msg, int argc,
						 char **argv, enum id_input id)
{
	struct nlattr *params;
	int rfkill_state;

	if (argc != 1)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_HOST_SET_SW_RFKILL_STATE);

	params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
	if (!params)
		return -ENOBUFS;

	if (strcmp(argv[0], "on") == 0)
		rfkill_state = IWL_VENDOR_SW_RFKILL_ON;
	else if (strcmp(argv[0], "off") == 0)
		rfkill_state = IWL_VENDOR_SW_RFKILL_OFF;
	else
		return 1;

	NLA_PUT_U8(msg, IWL_MVM_VENDOR_ATTR_SW_RFKILL_STATE, rfkill_state);
	nla_nest_end(msg, params);

	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, set_sw_rfkill_state, "<on|off",
	NL80211_CMD_VENDOR, 0, CIB_NETDEV, handle_iwl_vendor_set_sw_rfkill_state,
	"Set SW RF Kill state");

static void parse_time_sync_msmt_event(unsigned int id,
				       unsigned int subcmd,
				       struct nlattr *data)
{
	int err;
	struct nlattr *tb[MAX_IWL_MVM_VENDOR_ATTR + 1];

	err = nla_parse_nested(tb, MAX_IWL_MVM_VENDOR_ATTR, data, NULL);
	if (err) {
		printf(" Invalid time sync msmt event");
		return;
	}

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T1])
		printf("\n\ttime_sync_t1: %lu\n",
		       nla_get_u64(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T1]));

        if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T2])
		printf("\ttime_sync_t2: %lu\n",
		       nla_get_u64(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T2]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T3])
		printf("\ttime_sync_t3: %lu\n",
		       nla_get_u64(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T3]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T4])
		printf("\ttime_sync_t4: %lu\n",
		       nla_get_u64(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T4]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_DIALOG_TOKEN])
		printf("\tdialog_token: %d\n",
		       nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_DIALOG_TOKEN]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_FUP_DIALOG_TOKEN])
		printf("\tfup_dialog_token: %d\n",
		       nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_FUP_DIALOG_TOKEN]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T1_MAX_ERROR])
		printf("\tt1_error: %d\n",
		       nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T1_MAX_ERROR]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T2_MAX_ERROR])
		printf("\tt2_error: %d\n",
		       nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T2_MAX_ERROR]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T3_MAX_ERROR])
		printf("\tt3_error: %d\n",
		       nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T3_MAX_ERROR]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T4_MAX_ERROR])
		printf("\tt4_error: %d\n",
		       nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_T4_MAX_ERROR]));

	if (tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_VS_DATA])
		iw_hexdump("\tVendor_data",
			   nla_data(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_VS_DATA]),
			   nla_len(tb[IWL_MVM_VENDOR_ATTR_TIME_SYNC_VS_DATA]));
}

VENDOR_EVENT(INTEL_OUI, IWL_MVM_VENDOR_CMD_TIME_SYNC_MSMT_EVENT,
	     parse_time_sync_msmt_event);

static int print_ppag_table_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *data = parse_vendor_reply(msg);
	struct nlattr *attr[MAX_IWL_MVM_VENDOR_ATTR + 1], *chain;
	int i, len, n_sub_bands;
	char chains[] = { 'A', 'B' };

	if (!data)
		return NL_SKIP;
	if (nla_parse_nested(attr, MAX_IWL_MVM_VENDOR_ATTR, data, NULL)) {
		printf("Failed to get PPAG table\n");
		return NL_SKIP;
	}

	if (!attr[IWL_MVM_VENDOR_ATTR_PPAG_NUM_SUB_BANDS] ||
	    !attr[IWL_MVM_VENDOR_ATTR_PPAG_TABLE]) {
		fprintf(stderr, "PPAG missing info\n");
		return NL_SKIP;
	}

	n_sub_bands = nla_get_u32(attr[IWL_MVM_VENDOR_ATTR_PPAG_NUM_SUB_BANDS]);

	nla_for_each_attr(chain,
			  (struct nlattr *)nla_data(attr[IWL_MVM_VENDOR_ATTR_PPAG_TABLE]),
			  nla_len(attr[IWL_MVM_VENDOR_ATTR_PPAG_TABLE]), len) {
		__s8* values = nla_data(chain);

		if (nla_type(chain) > (int)ARRAY_SIZE(chains)) {
			printf("Too many attributes for SAR profile\n");
			return -EINVAL;
		}

		if (n_sub_bands != nla_len(chain)) {
		    printf("Too many or too few PPAG values\n");
		    return -EINVAL;
		}

		printf("Chain %c: ", chains[nla_type(chain) - 1]);
		for (i = 0; i < n_sub_bands; i++)
			printf("%d ", values[i]);
		printf("\n");
	}
	return NL_SKIP;
}

static int handle_iwl_vendor_ppag_get_table(struct nl80211_state *state,
					    struct nl_msg *msg,
					    int argc, char **argv,
					    enum id_input id)
{
	int num;

	if (argc != 0)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_PPAG_GET_TABLE);

	register_handler(print_ppag_table_handler, &num);
	return 0;

nla_put_failure:
	return -ENOBUFS;
	printf("in nla_put_failure\n");
}

COMMAND(iwl, ppag_get_table, "",
	NL80211_CMD_VENDOR, 0,
	CIB_NETDEV,
	handle_iwl_vendor_ppag_get_table, "");

#define SAR_NUM_PROFILES 4
#define SAR_NUM_CHAINS_V1 2
#define SAR_NUM_CHAINS_V2 4
#define SAR_NUM_SUB_BANDS_V1 5
#define SAR_NUM_SUB_BANDS_V2 11

static int print_sar_table_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *data = parse_vendor_reply(msg);
	struct nlattr *attr[MAX_IWL_MVM_VENDOR_ATTR + 1];
	struct nlattr *profile, *chain;
	char *chains[] = { "A" , "B", "CDB-A", "CDB-B" };
	int profs, i, len, n_chains, n_subbands;

	if (!data)
		return NL_SKIP;

	if (nla_parse_nested(attr, MAX_IWL_MVM_VENDOR_ATTR, data, NULL)) {
		printf("Failed to get the SAR table\n");
		return NL_SKIP;
	}

	if (!attr[IWL_MVM_VENDOR_ATTR_SAR_TABLE] ||
	    !attr[IWL_MVM_VENDOR_ATTR_SAR_VER])
		return NL_SKIP;

	/* determine num of chains and num of sub-bands */
	if (nla_get_u32(attr[IWL_MVM_VENDOR_ATTR_SAR_VER]) == 6) {
		n_chains = SAR_NUM_CHAINS_V2;
		n_subbands = SAR_NUM_SUB_BANDS_V2;
	} else {
		n_chains = SAR_NUM_CHAINS_V1;
		n_subbands = SAR_NUM_SUB_BANDS_V1;
	}

	nla_for_each_nested(profile, attr[IWL_MVM_VENDOR_ATTR_SAR_TABLE], profs) {
		if (nla_type(profile) > SAR_NUM_PROFILES) {
			printf("Too many attributes for SAR table\n");
			return -EINVAL;
		}

		printf("SAR profile #%d:\n", nla_type(profile));

		nla_for_each_attr(chain, (struct nlattr *)nla_data(profile), nla_len(profile), len) {
			__u8 *values = nla_data(chain);

			if(nla_type(chain) > n_chains)
				break;

			printf("Chain %s:", chains[nla_type(chain) - 1]);
			for(i = 0; i < nla_len(chain) && i < n_subbands; i++)
				printf(" %d", values[i]);
			printf("\n");
		}
	}
	return NL_SKIP;
}

static int handle_iwl_vendor_sar_get_table(struct nl80211_state *state,
					   struct nl_msg *msg,
					   int argc, char** argv,
					   enum id_input id)
{
	if (argc != 0)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_SAR_GET_TABLE);

	register_handler(print_sar_table_handler, NULL);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, sar_get_table, "",
	NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_sar_get_table, "");

#define GEO_SAR_NUM_PROFILES 3

static int print_geo_table_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *data = parse_vendor_reply(msg);
	struct nlattr *attr[MAX_IWL_MVM_VENDOR_ATTR + 1];
	struct nlattr *profile;
	int profs, ret, prof_num, n_bands;

	if (!data)
		return NL_SKIP;

	if (nla_parse_nested(attr, MAX_IWL_MVM_VENDOR_ATTR, data, NULL)) {
		        printf("Failed to get SAR geographic table\n");
			        return NL_SKIP;
	}
	if (!attr[IWL_MVM_VENDOR_ATTR_GEO_SAR_TABLE] ||
	    !attr[IWL_MVM_VENDOR_ATTR_GEO_SAR_VER])
			          return NL_SKIP;
	/* determine num of bands*/
	n_bands = (nla_get_u32(attr[IWL_MVM_VENDOR_ATTR_GEO_SAR_VER]) == 2) ?
		GEO_SAR_NUM_BANDS_V2 : GEO_SAR_NUM_BANDS_V1;

	nla_for_each_nested(profile, attr[IWL_MVM_VENDOR_ATTR_GEO_SAR_TABLE],
			    profs) {
		prof_num = nla_type(profile);
		if (nla_type(profile) > GEO_SAR_NUM_PROFILES) {
			printf("Too many nested attributes for SAR GEO table\n");
			return -EINVAL;
		}

		ret = print_geo_profile(profile, n_bands, &prof_num);
		if (ret)
			return ret;
	}

	return NL_SKIP;
}

static int handle_iwl_vendor_sar_get_geo_table(struct nl80211_state *state,
					       struct nl_msg *msg,
					       int argc, char** argv,
					       enum id_input id)
{
	if (argc != 0)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_GEO_SAR_GET_TABLE);

	register_handler(print_geo_table_handler, NULL);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, sar_get_geo_table, "",
	NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_sar_get_geo_table, "");
