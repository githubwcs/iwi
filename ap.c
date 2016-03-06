#include <errno.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include "nl80211.h"
#include "iw.h"

SECTION(ap);

static int handle_start_ap(struct nl80211_state *state,
			   struct nl_msg *msg, int argc, char **argv,
			   enum id_input id)
{
	char *end;
	int val, len;
	char buf[2304];

	if (argc < 6)
		return 1;

	/* SSID */
	NLA_PUT(msg, NL80211_ATTR_SSID, strlen(argv[0]), argv[0]);
	argv++;
	argc--;

	/* freq */
	val = strtoul(argv[0], &end, 10);
	if (*end != '\0')
		return -EINVAL;

	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, val);
	argv++;
	argc--;

	/* beacon interval */
	val = strtoul(argv[0], &end, 10);
	if (*end != '\0')
		return -EINVAL;

	NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, val);
	argv++;
	argc--;

	/* dtim */
	val = strtoul(argv[0], &end, 10);
	if (*end != '\0')
		return -EINVAL;

	NLA_PUT_U32(msg, NL80211_ATTR_DTIM_PERIOD, val);
	argv++;
	argc--;

	/* beacon head must be provided */
	if (strcmp(argv[0], "head") != 0)
		return -1;
	argv++;
	argc--;

	len = strlen(argv[0]);
	if (!len || (len % 2))
		return -EINVAL;

	if (!hex2bin(&argv[0][0], buf))
		return -EINVAL;

	NLA_PUT(msg, NL80211_ATTR_BEACON_HEAD, (len / 2), &buf);
	argv++;
	argc--;

	if (!argc)
		return 0;

	/* tail is optional */
	if (strcmp(argv[0], "tail") == 0) {
		argv++;
		argc--;

		if (!argc)
			return -EINVAL;

		len = strlen(argv[0]);
		if (!len || (len % 2))
			return -EINVAL;

		if (!hex2bin(&argv[0][0], buf))
			return -EINVAL;

		NLA_PUT(msg, NL80211_ATTR_BEACON_TAIL, (len / 2), &buf);
		argv++;
		argc--;
	}

	if (!argc)
		return 0;

	if (strcmp(*argv, "key") != 0 && strcmp(*argv, "keys") != 0)
		return 1;

	argv++;
	argc--;

	return parse_keys(msg, argv, argc);
 nla_put_failure:
	return -ENOSPC;
}
COMMAND(ap, start, "",
	NL80211_CMD_NEW_BEACON, 0, CIB_NETDEV, handle_start_ap,
	"<SSID> <freq in MHz> <beacon interval in TU> <DTIM period> <head>"
	" <beacon head in hexadecimal> [<tail> <beacon tail in hexadecimal>]"
	" [key0:abcde d:1:6162636465]\n");

static int handle_stop_ap(struct nl80211_state *state,
			  struct nl_msg *msg,
			  int argc, char **argv,
			  enum id_input id)
{
	return 0;
}
COMMAND(ap, stop, "",
	NL80211_CMD_DEL_BEACON, 0, CIB_NETDEV, handle_stop_ap,
	"Stop AP functionality\n");