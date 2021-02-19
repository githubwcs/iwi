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

#define WLAN_FC_TYPE_MGMT                               0
 /* management */
#define WLAN_FC_STYPE_ACTION                            0x0D
/*To get frame control field */
#define SET_FRAME_CTRL(type, stype) htole16((type << 2) | (stype << 4))

/* Action frame categories */
#define WLAN_ACTION_UNPROTECTED_WNM	0x0B
#define WLAN_ACTION_PUBLIC				0x04
#define WLAN_PUBLIC_FTM_MSMT			0x21
//#define WLAN_PUBLIC_FTM_REQUEST             32

#define TOD_SIZE		6
#define TOA_SIZE		6
//#define VS_DATA_SIZE	80

struct ieee80211_frame_hdr {
	__le16 frame_control;
	__le16 duration_id;
        __u8 da[6];
        __u8 sa[6];
        __u8 bssid[6];
        __le16 seq_ctrl;
	/* followed by '__u8 addr4[6];' if ToDS and FromDS is set in data frame
	 */
} STRUCT_PACKED;

#define FRAME_HDRLEN (sizeof(struct ieee80211_frame_hdr))

