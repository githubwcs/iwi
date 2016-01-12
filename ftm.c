#include <errno.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <inttypes.h>

#include "nl80211.h"
#include "iw.h"

SECTION(ftm);

static int handle_ftm_info(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *info[NL80211_FTM_INFO_MAX + 1];
	static struct nla_policy info_policy[NL80211_FTM_INFO_MAX + 1] = {
		[NL80211_FTM_INFO_SUCCESS_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_INFO_PARTIAL_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_INFO_FAILED_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_INFO_ASAP_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_INFO_NON_ASAP_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_INFO_TOTAL_DURATION_MSEC]	= { .type = NLA_U64 },
		[NL80211_FTM_INFO_UNKNOWN_TRIGGERS_NUM]	= { .type = NLA_U32 },
		[NL80211_FTM_INFO_RESCHEDULE_REQUESTS_NUM]
							= { .type = NLA_U32 },
		[NL80211_FTM_INFO_OUT_OF_WINDOW_TRIGGERS_NUM]
							= { .type = NLA_U32 },
	};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_FTM_RESPONDER_INFO]) {
		fprintf(stderr, "FTM responder info is missing");
		return NL_SKIP;
	}

	nla_parse(info, NL80211_REG_RULE_ATTR_MAX,
		  nla_data(tb[NL80211_ATTR_FTM_RESPONDER_INFO]),
		  nla_len(tb[NL80211_ATTR_FTM_RESPONDER_INFO]),
		  info_policy);

	printf("FTM responder info:\n");

	if (info[NL80211_FTM_INFO_SUCCESS_NUM])
		printf("\tSuccess num %u\n",
		       nla_get_u32(info[NL80211_FTM_INFO_SUCCESS_NUM]));

	if (info[NL80211_FTM_INFO_PARTIAL_NUM])
		printf("\tPartial success num %u\n",
		       nla_get_u32(info[NL80211_FTM_INFO_PARTIAL_NUM]));

	if (info[NL80211_FTM_INFO_FAILED_NUM])
		printf("\tFailed num %u\n",
		       nla_get_u32(info[NL80211_FTM_INFO_FAILED_NUM]));

	if (info[NL80211_FTM_INFO_ASAP_NUM])
		printf("\tASAP success num %u\n",
		       nla_get_u32(info[NL80211_FTM_INFO_ASAP_NUM]));

	if (info[NL80211_FTM_INFO_NON_ASAP_NUM])
		printf("\tNon ASAP num %u\n",
		       nla_get_u32(info[NL80211_FTM_INFO_NON_ASAP_NUM]));

	if (info[NL80211_FTM_INFO_TOTAL_DURATION_MSEC])
		printf("\tTotal duration %" PRIu64 "\n",
		       nla_get_u64(info[NL80211_FTM_INFO_TOTAL_DURATION_MSEC]));

	if (info[NL80211_FTM_INFO_UNKNOWN_TRIGGERS_NUM])
		printf("\tUnknown triggers num %u\n",
		       nla_get_u32(info[NL80211_FTM_INFO_UNKNOWN_TRIGGERS_NUM]));

	if (info[NL80211_FTM_INFO_RESCHEDULE_REQUESTS_NUM])
		printf("\tRescheduled requests num %u\n",
		       nla_get_u32(info[NL80211_FTM_INFO_RESCHEDULE_REQUESTS_NUM]));

	if (info[NL80211_FTM_INFO_OUT_OF_WINDOW_TRIGGERS_NUM])
		printf("\tOut of window num %u\n",
		       nla_get_u32(info[NL80211_FTM_INFO_OUT_OF_WINDOW_TRIGGERS_NUM]));

	return NL_SKIP;
}

static int handle_ftm_get_info(struct nl80211_state *state,
			       struct nl_msg *msg, int argc, char **argv,
			       enum id_input id)
{
	register_handler(handle_ftm_info, NULL);
	return 0;
}

COMMAND(ftm, get_info, "",
	NL80211_CMD_GET_FTM_RESPONDER_INFO, 0, CIB_NETDEV, handle_ftm_get_info,
	"Get FTM responder information.\n");
