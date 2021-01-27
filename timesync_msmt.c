#include "timesync_msmt.h"

SECTION(timesync_msmt);
static int build_timesync_frame(struct nl_msg *msg, u8 *data, int *data_len,
				const char *file)				
{
	u8 category;
	u8 action;
	struct ieee80211_frame_hdr *hdr;
	FILE *input;
        char line[256];
        int line_num, trigger;
	unsigned char init_addr[ETH_ALEN];
	unsigned char resp_addr[ETH_ALEN];
	char *bw = NULL, *tmp, *pos, *save_ptr, *delims = " \t\n";
	u32 freq = 0, cf1 = 0, cf2 = 0;
	int ret, i;


        input = fopen(file, "r");
        if (!input) {
                int err = errno;

                printf("Failed to open file: %s\n", strerror(err));
                return -err;
        }

        for (line_num = 1; fgets(line, sizeof(line), input); line_num++) {
                if (line[0] == '#')
                        continue;

		pos = strtok_r(line, delims, &save_ptr);
		while (pos) {
			if (strncmp(pos, "cf=", 3) == 0) {
			    freq = strtol(pos + 3, &tmp, 0);
			    if (*tmp) {
                            	printf("Invalid cf value!\n");
				return HANDLER_RET_USAGE;
			    }
			    printf("KD:Freq=%d\n", freq);
			} else if (strncmp(pos, "bw=", 3) == 0) {
				   bw = pos + 3;
			 } else if (strncmp(pos, "cf1=", 4) == 0) {
				    cf1 = strtol(pos + 4, &tmp, 0);
				    if (*tmp) {
					printf("Invalid cf1 value!\n");
					return HANDLER_RET_USAGE;
				    }
			 } else if (strncmp(pos, "cf2=", 4) == 0) {
				    cf2 = strtol(pos + 4, &tmp, 0);
				    if (*tmp) {
					printf("Invalid cf2 value!\n");
					return HANDLER_RET_USAGE;
				    }
			 } else if(strncmp(pos, "initiator_addr=", 15) == 0) {
			  	   //memcpy(init_addr, pos + 15, ETH_ALEN); 
				   ret = mac_addr_a2n(init_addr, pos + 15);
				   if (ret < 0)
				     return -EINVAL;
				  for(i = 0; i<6;i++)
				      printf("KD:addr[%d]=%x\n",i,init_addr[i]);
			 } else if(strncmp(pos, "responder_addr=", 15) == 0) {
				 ret = mac_addr_a2n(resp_addr, pos + 15);
				 if (ret < 0)
				     return -EINVAL;
				  for(i = 0; i<6;i++)
				      printf("KD:addr[%d]=%x\n",i,resp_addr[i]);
			 }else if(strncmp(pos, "trigger=", 8) == 0) {
				  trigger = strtol(pos + 8, &tmp, 0);
				  printf("KD:trigger = %d\n",trigger);
				  if (*tmp) {
				      printf("Invalid trigger value!\n");
				      return HANDLER_RET_USAGE;
				    }
			}

			 pos = strtok_r(NULL, delims, &save_ptr);
		}
	}

	hdr = (struct ieee80211_frame_hdr *)malloc(sizeof(struct ieee80211_frame_hdr));
	hdr->frame_control = SET_FRAME_CTRL(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);
	memcpy(hdr->da, resp_addr, ETH_ALEN);
	memcpy(hdr->sa, init_addr, ETH_ALEN);
	memcpy(hdr->bssid, resp_addr, ETH_ALEN); 

	memcpy(data, hdr, sizeof(struct ieee80211_frame_hdr));
	data_len += FRAME_HDRLEN;

	/*Add categoty field*/
	category = WLAN_ACTION_UNPROTECTED_WNM;
	memcpy(data + FRAME_HDRLEN, &category, sizeof(u8));
	data_len += sizeof(u8);

	/*Add action field*/
	action = WLAN_ACTION_PUBLIC;	
	memcpy(data + FRAME_HDRLEN + sizeof(u8), &action, sizeof(u8));
	data_len += sizeof(u8);

	/*Add trigger field*/
	memcpy(data + FRAME_HDRLEN + sizeof(u16), &trigger, sizeof(u8));
	data_len += sizeof(u8);

	/*TODO Add optional FTM params*/

	/*set channel related configuration*/
	if (freq) {
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
	}
         if (cf1)
             nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, cf1);
         if (cf2)
             nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, cf2);
	  return 0;
}
		
static int handle_IFTM_send_req(struct nl80211_state *state, struct nl_msg *msg,
			  int argc, char **argv, enum id_input id)
{

	int err, i;
	u8 data[1024];
	int data_len = 0;
	const char *file;
	int ret = 0;

	file = argv[0];
         argc--;
         argv++;
	 
	 ret = build_timesync_frame(msg, data, &data_len, file);
	 if(ret) {
	    printf("Error: unable to build time sync frames %d\n", ret);
	    return ret;
	 }
	
	if (nla_put(msg, NL80211_ATTR_FRAME, data_len, data) < 0) {
	            printf("Error in sending IFTMR");
		    return -EINVAL;
	 }
	
	return 0;	
}


COMMAND(timesync_msmt, send_iftmr, "<config-file>", NL80211_CMD_FRAME, 0,
CIB_NETDEV, handle_IFTM_send_req, NULL);
