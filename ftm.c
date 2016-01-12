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

static int handle_ftm_stats(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *info[NL80211_FTM_STATS_MAX + 1];
	static struct nla_policy info_policy[NL80211_FTM_STATS_MAX + 1] = {
		[NL80211_FTM_STATS_SUCCESS_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_STATS_PARTIAL_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_STATS_FAILED_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_STATS_ASAP_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_STATS_NON_ASAP_NUM]		= { .type = NLA_U32 },
		[NL80211_FTM_STATS_TOTAL_DURATION_MSEC]	= { .type = NLA_U64 },
		[NL80211_FTM_STATS_UNKNOWN_TRIGGERS_NUM]	= { .type = NLA_U32 },
		[NL80211_FTM_STATS_RESCHEDULE_REQUESTS_NUM]
							= { .type = NLA_U32 },
		[NL80211_FTM_STATS_OUT_OF_WINDOW_TRIGGERS_NUM]
							= { .type = NLA_U32 },
	};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_FTM_RESPONDER_STATS]) {
		fprintf(stderr, "FTM responder statistics are missing");
		return NL_SKIP;
	}

	nla_parse(info, NL80211_REG_RULE_ATTR_MAX,
		  nla_data(tb[NL80211_ATTR_FTM_RESPONDER_STATS]),
		  nla_len(tb[NL80211_ATTR_FTM_RESPONDER_STATS]),
		  info_policy);

	printf("FTM responder stats:\n");

	if (info[NL80211_FTM_STATS_SUCCESS_NUM])
		printf("\tSuccess num %u\n",
		       nla_get_u32(info[NL80211_FTM_STATS_SUCCESS_NUM]));

	if (info[NL80211_FTM_STATS_PARTIAL_NUM])
		printf("\tPartial success num %u\n",
		       nla_get_u32(info[NL80211_FTM_STATS_PARTIAL_NUM]));

	if (info[NL80211_FTM_STATS_FAILED_NUM])
		printf("\tFailed num %u\n",
		       nla_get_u32(info[NL80211_FTM_STATS_FAILED_NUM]));

	if (info[NL80211_FTM_STATS_ASAP_NUM])
		printf("\tASAP success num %u\n",
		       nla_get_u32(info[NL80211_FTM_STATS_ASAP_NUM]));

	if (info[NL80211_FTM_STATS_NON_ASAP_NUM])
		printf("\tNon ASAP num %u\n",
		       nla_get_u32(info[NL80211_FTM_STATS_NON_ASAP_NUM]));

	if (info[NL80211_FTM_STATS_TOTAL_DURATION_MSEC])
		printf("\tTotal duration %" PRIu64 "\n",
		       nla_get_u64(info[NL80211_FTM_STATS_TOTAL_DURATION_MSEC]));

	if (info[NL80211_FTM_STATS_UNKNOWN_TRIGGERS_NUM])
		printf("\tUnknown triggers num %u\n",
		       nla_get_u32(info[NL80211_FTM_STATS_UNKNOWN_TRIGGERS_NUM]));

	if (info[NL80211_FTM_STATS_RESCHEDULE_REQUESTS_NUM])
		printf("\tRescheduled requests num %u\n",
		       nla_get_u32(info[NL80211_FTM_STATS_RESCHEDULE_REQUESTS_NUM]));

	if (info[NL80211_FTM_STATS_OUT_OF_WINDOW_TRIGGERS_NUM])
		printf("\tOut of window num %u\n",
		       nla_get_u32(info[NL80211_FTM_STATS_OUT_OF_WINDOW_TRIGGERS_NUM]));

	return NL_SKIP;
}

static int handle_ftm_get_stats(struct nl80211_state *state,
			       struct nl_msg *msg, int argc, char **argv,
			       enum id_input id)
{
	register_handler(handle_ftm_stats, NULL);
	return 0;
}

COMMAND(ftm, get_stats, "",
	NL80211_CMD_GET_FTM_RESPONDER_STATS, 0, CIB_NETDEV, handle_ftm_get_stats,
	"Get FTM responder statistics.\n");
