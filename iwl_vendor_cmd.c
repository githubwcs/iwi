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
	[IWL_MVM_VENDOR_ATTR_VIF_LL] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_LL] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_VIF_LOAD] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_LOAD] = { .type = NLA_U8 },
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

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
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

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
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

	if (argc != 0 && argc != 0)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_GET_SAR_PROFILE_INFO);

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
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

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
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

	config = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
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

static void parse_tcm_event(struct nlattr *data)
{
	struct nlattr *attrs[NUM_IWL_MVM_VENDOR_ATTR];

	if (nla_parse_nested(attrs, MAX_IWL_MVM_VENDOR_ATTR, data, iwl_vendor_policy) ||
	    !attrs[IWL_MVM_VENDOR_ATTR_LL] || !attrs[IWL_MVM_VENDOR_ATTR_LOAD]) {
		printf("Ignore invalid TCM data");
		return;
	}

	printf(" ==> Intel TCM event: global (qos=%u, load=%u)",
	       nla_get_u8(attrs[IWL_MVM_VENDOR_ATTR_LL]),
	       nla_get_u8(attrs[IWL_MVM_VENDOR_ATTR_LOAD]));

	if (attrs[IWL_MVM_VENDOR_ATTR_VIF_ADDR] &&
	    attrs[IWL_MVM_VENDOR_ATTR_VIF_LL] &&
	    attrs[IWL_MVM_VENDOR_ATTR_VIF_LOAD]) {
		char addr[3 * ETH_ALEN];

		mac_addr_n2a(addr, nla_data(attrs[IWL_MVM_VENDOR_ATTR_VIF_ADDR]));
		printf(" vif(%s qos=%u, load=%u)", addr,
		       nla_get_u8(attrs[IWL_MVM_VENDOR_ATTR_VIF_LL]),
		       nla_get_u8(attrs[IWL_MVM_VENDOR_ATTR_VIF_LOAD]));
	}
}

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

	req = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
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

static const char const* phy2str[] =
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

static const char const* vendorwidth2str[] =
{
	[IWL_MVM_VENDOR_CHAN_WIDTH_20] = "20MHz",
	[IWL_MVM_VENDOR_CHAN_WIDTH_40] = "40MHz",
	[IWL_MVM_VENDOR_CHAN_WIDTH_80] = "80MHz",
	[IWL_MVM_VENDOR_CHAN_WIDTH_160] = "160MHz",
	[IWL_MVM_VENDOR_CHAN_WIDTH_80P80] = "80P80MHz",
};

static void parse_neighbor_report(struct nlattr *data)
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

void iwl_parse_event(__u32 vendor_id, struct nlattr **attrs)
{
	if (vendor_id != INTEL_OUI)
		return;

	switch (nla_get_u32(attrs[NL80211_ATTR_VENDOR_SUBCMD])) {
	case IWL_MVM_VENDOR_CMD_TCM_EVENT:
		parse_tcm_event(attrs[NL80211_ATTR_VENDOR_DATA]);
		break;
	case IWL_MVM_VENDOR_CMD_NEIGHBOR_REPORT_RESPONSE:
		parse_neighbor_report(attrs[NL80211_ATTR_VENDOR_DATA]);
		break;
	default:
		break;
	}
}
