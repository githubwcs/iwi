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

typedef __u16 u16;
typedef __u8 u8;
typedef __le16 le16;
typedef __u32 u32;

#define WLAN_FC_TYPE_MGMT                               0
 /* management */
 #define WLAN_FC_STYPE_ACTION                            13
/*To get frame control field */
#define SET_FRAME_CTRL(type, stype) htole16((type << 2) | (stype << 4))

/* Action frame categories */
  #define WLAN_ACTION_UNPROTECTED_WNM                     11
 #define WLAN_ACTION_PUBLIC                              4

struct ieee80211_frame_hdr {
	le16 frame_control;
	le16 duration_id;
        u8 da[6];
        u8 sa[6];
        u8 bssid[6];
        le16 seq_ctrl;
	/* followed by '__u8 addr4[6];' if ToDS and FromDS is set in data frame
	 */
} STRUCT_PACKED;

#define FRAME_HDRLEN (sizeof(struct ieee80211_frame_hdr))

