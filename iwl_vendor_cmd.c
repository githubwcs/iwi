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
	[IWL_MVM_VENDOR_ATTR_LQM_RESULT] = { .type = NLA_NESTED },
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

static int handle_iwl_vendor_start_lqm(struct nl80211_state *state,
				       struct nl_msg *msg, int argc,
				       char **argv, enum id_input id)
{
	struct nlattr *limits;
	unsigned long val;
	char *end;

	if (argc != 2)
		return 1;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_QUALITY_MEASUREMENTS);

	limits = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	if (!limits)
		return -ENOBUFS;

	val = strtoul(argv[0], &end, 10);
	if (end == argv[0] || *end)
		return 1;
	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_LQM_DURATION, val);

	val = strtoul(argv[1], &end, 10);
	if (end == argv[1] || *end)
		return 1;
	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_LQM_TIMEOUT, val);

	nla_nest_end(msg, limits);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}
COMMAND(iwl, lqm, "duration(us) timeout(us)", NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_start_lqm, "");

static const char const* width2str[] =
{
	[NL80211_CHAN_WIDTH_20_NOHT] = "20noHT",
	[NL80211_CHAN_WIDTH_20] = "HT20",
	[NL80211_CHAN_WIDTH_40] = "HT40",
	[NL80211_CHAN_WIDTH_80] = "VHT80",
	[NL80211_CHAN_WIDTH_80P80] = "VHT80+80",
	[NL80211_CHAN_WIDTH_160] = "VHT160",
};

static const char const* lqmstatus2str[] =
{
	[IWL_MVM_VENDOR_LQM_STATUS_SUCCESS] = "Success",
	[IWL_MVM_VENDOR_LQM_STATUS_TIMEOUT] = "Timeout",
	[IWL_MVM_VENDOR_LQM_STATUS_ABORT] = "Abort",
};

static void parse_lqm_event(struct nlattr *data)
{
	struct nlattr *lqm[NUM_IWL_MVM_VENDOR_LQM_RESULT];
	struct nlattr *attrs[NUM_IWL_MVM_VENDOR_ATTR];
	struct nlattr *sta_air_time;
	static struct nla_policy lqm_policy[] = {
		[IWL_MVM_VENDOR_ATTR_LQM_ACTIVE_STA_AIR_TIME] = { .type = NLA_NESTED },
		[IWL_MVM_VENDOR_ATTR_LQM_OTHER_STA] = { .type = NLA_U32 },
		[IWL_MVM_VENDOR_ATTR_LQM_MEAS_TIME] = { .type = NLA_U32 },
		[IWL_MVM_VENDOR_ATTR_LQM_RETRY_LIMIT] = { .type = NLA_U32 },
		[IWL_MVM_VENDOR_ATTR_LQM_MEAS_STATUS] = { .type = NLA_U32 },
	};
	int rem, i;

	if (nla_parse_nested(attrs, MAX_IWL_MVM_VENDOR_ATTR, data, iwl_vendor_policy) ||
	    !attrs[IWL_MVM_VENDOR_ATTR_LQM_RESULT] ||
	    !attrs[IWL_MVM_VENDOR_ATTR_WIPHY_FREQ] ||
	    !attrs[IWL_MVM_VENDOR_ATTR_CHANNEL_WIDTH] ||
	    !attrs[IWL_MVM_VENDOR_ATTR_CENTER_FREQ1]) {
		printf(" Ignore invalid LQM data");
		return;
	}

	printf(" ==> Intel LQM event: freq %dHz Width: %s",
	       nla_get_u32(attrs[IWL_MVM_VENDOR_ATTR_CENTER_FREQ1]),
	       width2str[nla_get_u32(attrs[IWL_MVM_VENDOR_ATTR_CHANNEL_WIDTH])]);

	if (nla_parse_nested(lqm, MAX_IWL_MVM_VENDOR_LQM_RESULT,
	    attrs[IWL_MVM_VENDOR_ATTR_LQM_RESULT], lqm_policy))
		printf("Bad internal data");

	if (!lqm[IWL_MVM_VENDOR_ATTR_LQM_ACTIVE_STA_AIR_TIME] ||
	    !lqm[IWL_MVM_VENDOR_ATTR_LQM_OTHER_STA] ||
	    !lqm[IWL_MVM_VENDOR_ATTR_LQM_MEAS_TIME] ||
	    !lqm[IWL_MVM_VENDOR_ATTR_LQM_RETRY_LIMIT] ||
	    !lqm[IWL_MVM_VENDOR_ATTR_LQM_MEAS_STATUS])
		printf("Bad internal data");

	printf(" status: %s\n",
	       lqmstatus2str[nla_get_u32(lqm[IWL_MVM_VENDOR_ATTR_LQM_MEAS_STATUS])]);

	printf("\tMeasurement time: %dus\n", nla_get_u32(lqm[IWL_MVM_VENDOR_ATTR_LQM_MEAS_TIME]));
	printf("\tother stas: %dus\n", nla_get_u32(lqm[IWL_MVM_VENDOR_ATTR_LQM_OTHER_STA]));
	printf("\tretry limit: %d frames\n", nla_get_u32(lqm[IWL_MVM_VENDOR_ATTR_LQM_RETRY_LIMIT]));

	i = 0;
	nla_for_each_nested(sta_air_time, lqm[IWL_MVM_VENDOR_ATTR_LQM_ACTIVE_STA_AIR_TIME], rem)
		printf("\tSTA[%d]: %dus\n", i++, nla_get_u32(sta_air_time));
}

void iwl_parse_event(__u32 vendor_id, struct nlattr **attrs)
{
	if (vendor_id != INTEL_OUI)
		return;

	switch (nla_get_u32(attrs[NL80211_ATTR_VENDOR_SUBCMD])) {
	case IWL_MVM_VENDOR_CMD_TCM_EVENT:
		parse_tcm_event(attrs[NL80211_ATTR_VENDOR_DATA]);
		break;
	case IWL_MVM_VENDOR_CMD_QUALITY_MEASUREMENTS:
		parse_lqm_event(attrs[NL80211_ATTR_VENDOR_DATA]);
		break;
	default:
		break;
	}
}

static int handle_iwl_vendor_nan_faw_conf(struct nl80211_state *state,
					  struct nl_msg *msg,
					  int argc, char **argv,
					  enum id_input id)
{
	struct nlattr *attrs;

	if (argc != 2)
		return -EINVAL;

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, INTEL_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    IWL_MVM_VENDOR_CMD_NAN_FAW_CONF);

	attrs = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	if (!attrs)
		return -ENOBUFS;

	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_NAN_FAW_SLOTS, atoi(argv[0]));
	NLA_PUT_U32(msg, IWL_MVM_VENDOR_ATTR_NAN_FAW_FREQ, atoi(argv[1]));

	nla_nest_end(msg, attrs);
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

COMMAND(iwl, nan_faw, "<slots> <freq>", NL80211_CMD_VENDOR, 0,
	CIB_NETDEV, handle_iwl_vendor_nan_faw_conf, "");
