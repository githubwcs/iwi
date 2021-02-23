// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2021 Intel Corporation
 */

#include "time_sync.h"

SECTION(time_sync);

void serialize_data(__u64 num, __u8 *buf, int num_bytes_to_serialize)
{
	int count;

	if (!buf) {
		printf("Invalid buf value\n");
		return;
	}

	/* Start serializing the bytes */
	for (count = 0; count < (num_bytes_to_serialize - 1) ; count++) {
		buf[count] = num & 0xFF;
		num >>= 8;
	}

	/* Serialize the last byte */
	buf[count] = num & 0xFF;
}

static int build_time_sync_msmt_frame(struct nl_msg *msg, __u8 *data, int *data_len,
				      const char *file)
{
	__u8 category;
	__u8 action;
	struct ieee80211_frame_hdr *hdr;
	FILE *input;
	char line[256];
	int line_num;
	int ret;
	unsigned char init_addr[ETH_ALEN];
	unsigned char resp_addr[ETH_ALEN];
	char *tmp, *pos, *save_ptr, *delims = " \t\n";
	__u8 dialog_token = 0;
	__u8 follow_up = 0;
	__u8 tod[6] = {0};
	__u8 toa[6] = {0};
	__u16 tod_error = 0;
	__u16 toa_error = 0;
	__u64 temp = 0;
	__u8 vsie_element_id = 221;
	__u8 vsie_length = VS_OUI_SIZE + VS_DATA_SIZE;
	__u8 vsie_oui[VS_OUI_SIZE] = {0x00, 0x80, 0xC2};

	/* VS data is filled with sample values for testing purpose */
	__u8 vsie_data[VS_DATA_SIZE] = {0x00, 0x00, 0x00, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
					0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
					0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
					0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
					0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
					0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
					0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x01, 0x02, 0x03, 0x04,
					0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};

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
			if (strncmp(pos, "initiator_addr=", 15) == 0) {
				ret = mac_addr_a2n(init_addr, pos + 15);
				if (ret < 0)
					return -EINVAL;
			} else if (strncmp(pos, "responder_addr=", 15) == 0) {
				ret = mac_addr_a2n(resp_addr, pos + 15);
				if (ret < 0)
					return -EINVAL;
			} else if (strncmp(pos, "dialog_token=", 13) == 0) {
				dialog_token = strtol(pos + 13, &tmp, 0);
				if (*tmp) {
					printf("Invalid dialog_token value!\n");
					return -HANDLER_RET_USAGE;
				}
			} else if (strncmp(pos, "follow_up=", 10) == 0) {
				follow_up = strtol(pos + 10, &tmp, 0);
				if (*tmp) {
					printf("Invalid follow_up value!\n");
					return -HANDLER_RET_USAGE;
				}
			} else if (strncmp(pos, "tod=", 4) == 0) {
				temp = strtol(pos + 4, &tmp, 0);
				serialize_data(temp, tod, TOD_SIZE);
				if (*tod == 0) {
					printf("Invalid tod value!\n");
					return -HANDLER_RET_USAGE;
				}
			} else if (strncmp(pos, "toa=", 4) == 0) {
				temp = strtol(pos + 4, &tmp, 0);
				serialize_data(temp, toa, TOA_SIZE);
				if (*toa == 0) {
					printf("Invalid toa value!\n");
					return -HANDLER_RET_USAGE;
				}
			} else if (strncmp(pos, "tod_error=", 10) == 0) {
				tod_error = strtol(pos + 10, &tmp, 0);
				if (*tmp) {
					printf("Invalid cf value!\n");
					return -HANDLER_RET_USAGE;
				}
			} else if (strncmp(pos, "toa_error=", 10) == 0) {
				toa_error = strtol(pos + 10, &tmp, 0);
				if (*tmp) {
					printf("Invalid cf value!\n");
					return -HANDLER_RET_USAGE;
				}
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
	*(data + *data_len) = tod_error & 0xFF;
	*data_len += 1;
	*(data + *data_len) = tod_error >> 8;
	*data_len += 1;

	/* Add toa_error field */
	*(data + *data_len) = toa_error & 0xFF;
	*data_len += 1;
	*(data + *data_len) = toa_error >> 8;
	*data_len += 1;

	/* Add vendor specific IE*/
	*(data + *data_len) = vsie_element_id;
	*data_len += 1;

	*(data + *data_len) = vsie_length;
	*data_len += 1;

	memcpy(data + *data_len, &vsie_oui, VS_OUI_SIZE);
	*data_len += VS_OUI_SIZE;

	memcpy(data + *data_len, &vsie_data, VS_DATA_SIZE);
	*data_len += VS_DATA_SIZE;

	return 0;
}

static int handle_ftm_msmt_send_req(struct nl80211_state *state, struct nl_msg *msg,
				    int argc, char **argv, enum id_input id)
{
	__u8 data[1024];
	int data_len = 0;
	const char *file;
	int ret = 0;
	int i;

	file = argv[0];
	argc--;
	argv++;

	ret = build_time_sync_msmt_frame(msg, data, &data_len, file);
	if (ret) {
		printf("Error: unable to build time sync msmt frame %d\n", ret);
		return ret;
	}

	if (nla_put(msg, NL80211_ATTR_FRAME, data_len, data) < 0) {
		printf("Error in sending FTM Msmt Req");
		return -EINVAL;
	}

	printf("FTM response (measurement) packet hex dump:\n");
	for (i = 0; i < data_len; i++)
		printf("0x%x, %d\n", data[i], data[i]);

	return 0;
}

COMMAND(time_sync, send_ftm_msmt, "<config-file>", NL80211_CMD_FRAME, 0,
	CIB_NETDEV, handle_ftm_msmt_send_req, NULL);
