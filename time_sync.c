#include "time_sync.h"

SECTION(time_sync);

static int build_time_sync_msmt_frame(struct nl_msg *msg, __u8 *data, int *data_len,
				const char *file)
{
	__u8 category;
	__u8 action;
	struct ieee80211_frame_hdr *hdr;
	FILE *input;
        char line[256];
        int line_num;
        int len;
	unsigned char init_addr[ETH_ALEN];
	unsigned char resp_addr[ETH_ALEN];
	char *tmp, *pos, *save_ptr, *delims = " \t\n";
	__u32 freq = 0, cf1 = 0, cf2 = 0;
	__u8 dialog_token = 0;
       __u8 follow_up = 0;
	__u8 tod[6] = {0};
       __u8 toa[6] = {0};
       __le16 tod_error = 0;
	__le16 toa_error = 0;
	int trigger = 0;
	int ret;
	int i;

	printf("Inside build_time_sync_msmt_frame\n");

        input = fopen(file, "r");
        if (!input) {
                int err = errno;

                printf("Failed to open file: %s\n", strerror(err));
                return -err;
        }

        printf("(%s) %d\n",__func__, __LINE__);

        for (line_num = 1; fgets(line, sizeof(line), input); line_num++) {
                if (line[0] == '#')
                        continue;

		printf("(%s) %d: Parsing Args\n",__func__, __LINE__);

		pos = strtok_r(line, delims, &save_ptr);
		while (pos) {
			printf("(%s) %d: pos:%s\n",__func__, __LINE__, pos);
			
			if (strncmp(pos, "cf=", 3) == 0) {
			    freq = strtol(pos + 3, &tmp, 0);
			    if (*tmp) {
				printf("Invalid cf value!\n");
				return HANDLER_RET_USAGE;
			    }
			    printf("cf=%d\n", freq);
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
				   ret = mac_addr_a2n(init_addr, pos + 15);
				   if (ret < 0)
				     return -EINVAL;
			 } else if(strncmp(pos, "responder_addr=", 15) == 0) {
				 ret = mac_addr_a2n(resp_addr, pos + 15);
				 if (ret < 0)
				     return -EINVAL;
			} else if (strncmp(pos, "dialog_token=", 13) == 0) {
				dialog_token = strtol(pos + 13, &tmp, 0);
				if (*tmp) {
					printf("Invalid dialog_token value!\n");
					return -HANDLER_RET_USAGE;
				}
				printf("dialog_token=%d\n", dialog_token);
			} else if (strncmp(pos, "follow_up=", 10) == 0) {
				follow_up = strtol(pos + 10, &tmp, 0);
				if (*tmp) {
					printf("Invalid follow_up value!\n");
					return -HANDLER_RET_USAGE;
				}
				printf("follow_up=%d\n", follow_up);
			}
			else if (strncmp(pos, "tod=", 4) == 0) {
				len = strlen(pos + 4);
				memcpy(tod, pos + 4, len);
				if (*tod == 0) {
					printf("Invalid tod value!\n");
					return -HANDLER_RET_USAGE;
				}
				for(i=0; i<6;i++)
					printf("tod[%d]=%d\n", i, tod[i]);
			} else if (strncmp(pos, "toa=", 4) == 0) {
				len = strlen(pos + 4);
				memcpy(toa, pos + 4, len);
				if (*toa == 0) {
					printf("Invalid toa value!\n");
					return -HANDLER_RET_USAGE;
				}
				for(i=0; i<6;i++)
					printf("toa[%d]=%d\n", i, toa[i]);
			} else if (strncmp(pos, "tod_error=", 10) == 0) {
			    tod_error = strtol(pos + 10, &tmp, 0);
			    if (*tmp) {
				printf("Invalid cf value!\n");
				return -HANDLER_RET_USAGE;
			    }
			    printf("tod_error=%d\n", tod_error);
			 } else if (strncmp(pos, "toa_error=", 10) == 0) {
			    toa_error = strtol(pos + 10, &tmp, 0);
			    if (*tmp) {
				printf("Invalid cf value!\n");
				return -HANDLER_RET_USAGE;
			    }
			    printf("toa_error=%d\n", toa_error);
			 }
			 
			 pos = strtok_r(NULL, delims, &save_ptr);
		}
	}

	hdr = (struct ieee80211_frame_hdr *)malloc(sizeof(struct ieee80211_frame_hdr));
	hdr->frame_control = SET_FRAME_CTRL(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);
	memcpy(hdr->da, init_addr, ETH_ALEN);
	memcpy(hdr->sa, resp_addr, ETH_ALEN);
	memcpy(hdr->bssid, resp_addr, ETH_ALEN);

	memcpy(data, hdr, sizeof(struct ieee80211_frame_hdr));
	*data_len += FRAME_HDRLEN;

	/* Add category field */
	category = WLAN_ACTION_PUBLIC;
	memcpy(data + *data_len, &category, sizeof(__u8));
	*data_len += sizeof(__u8);

#if 0
	/*Add action field*/
	action = WLAN_PUBLIC_FTM_REQUEST;
	memcpy(data + FRAME_HDRLEN + sizeof(__u8), &action, sizeof(__u8));
	*data_len += sizeof(__u8);

	/*Add trigger field*/
	memcpy(data + FRAME_HDRLEN + sizeof(__u16), &trigger, sizeof(__u8));
	*data_len += sizeof(__u8);
#endif

	/* Add action field */
	action = WLAN_PUBLIC_FTM_MSMT;
	memcpy(data + *data_len, &action, sizeof(__u8));
	*data_len += sizeof(__u8);

	/* Add dialog_token field */
	memcpy(data + *data_len, &dialog_token, sizeof(__u8));
	*data_len += sizeof(__u8);

	/* Add follow_up field */
	memcpy(data + *data_len, &follow_up, sizeof(__u8));
	*data_len += sizeof(__u8);

	/* Add tod field */
	memcpy(data + *data_len, &tod, TOD_SIZE * sizeof(__u8));
	*data_len += TOD_SIZE * sizeof(__u8);

	/* Add toa field */
	memcpy(data + *data_len, &toa, TOA_SIZE * sizeof(__u8));
	*data_len += TOA_SIZE * sizeof(__u8);

	/* Add tod_error field */
	memcpy(data + *data_len, &tod_error, sizeof(__le16));
	*data_len += sizeof(__le16);

	/* Add toa_error field */
	memcpy(data + *data_len, &toa_error, sizeof(__le16));
	*data_len += sizeof(__le16);

	/*set channel related configuration*/
	if (freq)
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
         if (cf1)
             nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, cf1);
         if (cf2)
             nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, cf2);

	printf("(%s) %d: Exiting build_time_sync_msmt_frame\n",__func__, __LINE__);
	return 0;
}

static int handle_ftm_msmt_send_req(struct nl80211_state *state, struct nl_msg *msg,
			  int argc, char **argv, enum id_input id)
{

	__u8 data[1024];
	int data_len = 0;
	const char *file;
	int ret = 0;

	file = argv[0];
         argc--;
         argv++;

         printf("Inside handle_ftm_msmt_send_req\n");

	 ret = build_time_sync_msmt_frame(msg, data, &data_len, file);
	 if(ret) {
	    printf("Error: unable to build time sync msmt frame %d\n", ret);
	    return ret;
	 }

	if (nla_put(msg, NL80211_ATTR_FRAME, data_len, data) < 0) {
	            printf("Error in sending FTM Msmt Req");
		    return -EINVAL;
	 }

	printf("printing raw data buffer\n");
	 for (int i=0; i < data_len; i++)
	 	printf("0x%x\n", data[i]);

	printf("(%s) %d: Exiting handle_ftm_msmt_send_req\n",__func__, __LINE__);
	return 0;
	//return HANDLER_RET_DONE;
}


COMMAND(time_sync, send_ftm_msmt, "<config-file>", NL80211_CMD_FRAME, 0,
CIB_NETDEV, handle_ftm_msmt_send_req, NULL);
