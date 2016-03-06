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
	struct nlattr *tcm[MAX_IWL_MVM_VENDOR_ATTR + 1];
	static struct nla_policy tcm_policy[NUM_IWL_MVM_VENDOR_ATTR] = {
		[IWL_MVM_VENDOR_ATTR_LOW_LATENCY] = { .type = NLA_FLAG },
		[IWL_MVM_VENDOR_ATTR_VIF_ADDR] = { .type = NLA_UNSPEC },
		[IWL_MVM_VENDOR_ATTR_VIF_LL] = { .type = NLA_U8 },
		[IWL_MVM_VENDOR_ATTR_LL] = { .type = NLA_U8 },
		[IWL_MVM_VENDOR_ATTR_VIF_LOAD] = { .type = NLA_U8 },
		[IWL_MVM_VENDOR_ATTR_LOAD] = { .type = NLA_U8 },
	};

	if (nla_parse_nested(tcm, MAX_IWL_MVM_VENDOR_ATTR, data, tcm_policy) ||
	    !tcm[IWL_MVM_VENDOR_ATTR_LL] || !tcm[IWL_MVM_VENDOR_ATTR_LOAD]) {
		printf("Ignore invalid TCM data");
		return;
	}

	printf(" ==> Intel TCM event: global (qos=%u, load=%u)",
	       nla_get_u8(tcm[IWL_MVM_VENDOR_ATTR_LL]),
	       nla_get_u8(tcm[IWL_MVM_VENDOR_ATTR_LOAD]));

	if (tcm[IWL_MVM_VENDOR_ATTR_VIF_ADDR] &&
	    tcm[IWL_MVM_VENDOR_ATTR_VIF_LL] &&
	    tcm[IWL_MVM_VENDOR_ATTR_VIF_LOAD]) {
		char addr[3 * ETH_ALEN];

		mac_addr_n2a(addr, nla_data(tcm[IWL_MVM_VENDOR_ATTR_VIF_ADDR]));
		printf(" vif(%s qos=%u, load=%u)", addr,
		       nla_get_u8(tcm[IWL_MVM_VENDOR_ATTR_VIF_LL]),
		       nla_get_u8(tcm[IWL_MVM_VENDOR_ATTR_VIF_LOAD]));
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
