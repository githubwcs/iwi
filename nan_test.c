#include <net/if.h>
#include <errno.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <ctype.h>
#include "nl80211.h"
#include "iw.h"

#define NAN_NONCE_LEN   32
#define NAN_KCK_MAX_LEN 24
#define NAN_KEK_MAX_LEN 32
#define NAN_TK_MAX_LEN  32
#define WLAN_NAN_NONCE_LEN 32

#define NAN_PTK_LABEL       "NAN Pairwise key expansion"
#define NAN_PMKID_LABEL     "NAN PMK Name"

#define SHA256_MAC_LEN 32
#define SHA384_MAC_LEN 48

struct ieee80211_nan_ptk {
	unsigned char kck[NAN_KCK_MAX_LEN];
	unsigned char kek[NAN_KEK_MAX_LEN];
	unsigned char tk[NAN_TK_MAX_LEN];

	size_t kck_len;
	size_t kek_len;
	size_t tk_len;
};

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
/* Compatibility wrappers for older versions. */
static HMAC_CTX * HMAC_CTX_new(void)
{
	HMAC_CTX *ctx = malloc(sizeof(*ctx));
	if (ctx)
		HMAC_CTX_init(ctx);
	return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (!ctx)
		return;
	HMAC_CTX_cleanup(ctx);
	free(ctx);
}
#endif

/* hmac using openssl */
static int openssl_hmac_vector(const EVP_MD *type,
			       const unsigned char *key, size_t key_len,
			       size_t num_elem, const unsigned char *addr[],
			       const size_t *len,
			       unsigned char *mac, unsigned int mdlen)
{
	HMAC_CTX *ctx;
	size_t i;
	int res;

	ctx = HMAC_CTX_new();
	if (!ctx)
		return -1;
	res = HMAC_Init_ex(ctx, key, key_len, type, NULL);
	if (res != 1)
		goto done;

	for (i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	res = HMAC_Final(ctx, mac, &mdlen);
done:
	HMAC_CTX_free(ctx);

	return res == 1 ? 0 : -1;
}

static int hmac_sha256_vector(const unsigned char *key, size_t key_len,
			      size_t num_elem, const unsigned char *addr[],
			      const size_t *len, unsigned char *mac)
{
	return openssl_hmac_vector(EVP_sha256(), key, key_len, num_elem, addr,
				   len, mac, 32);
}

static int hmac_sha384_vector(const unsigned char *key, size_t key_len,
			      size_t num_elem, const unsigned char *addr[],
			      const size_t *len, unsigned char *mac)
{
	return openssl_hmac_vector(EVP_sha384(), key, key_len, num_elem, addr,
				   len, mac, 32);
}

static void WPA_PUT_LE16(unsigned char *a, unsigned short val)
{
	a[1] = (unsigned char)(val >> 8);
	a[0] = (unsigned char)(val & 0xff);
}

int nan_kdf(const EVP_MD *type,
	    const unsigned char *key, size_t key_len, const char *label,
	    const unsigned char *data, size_t data_len,
	    unsigned char *buf, size_t buf_len_bits)
{
	unsigned short counter = 1;
	size_t pos, plen, mac_len;
	unsigned char *hash;
	int (*func)(const unsigned char *, size_t,
		    size_t, const unsigned char *addr[],
		    const size_t *, unsigned char *);

	const unsigned char *addr[4];
	size_t len[4];
	unsigned char counter_le[2], length_le[2];
	size_t buf_len = (buf_len_bits + 7) / 8;
	int ret;

	if (type == EVP_sha256()) {
		mac_len = SHA256_MAC_LEN;
		func = hmac_sha256_vector;
	} else if (type == EVP_sha384()) {
		mac_len = SHA384_MAC_LEN;
		func = hmac_sha384_vector;
	} else
		return -EINVAL;

	hash = malloc(mac_len);
	if (!hash)
		return -ENOBUFS;

	addr[0] = counter_le;
	len[0] = 2;
	addr[1] = (unsigned char *) label;
	len[1] = strlen(label);
	addr[2] = data;
	len[2] = data_len;
	addr[3] = length_le;
	len[3] = sizeof(length_le);

	WPA_PUT_LE16(length_le, buf_len_bits);
	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		WPA_PUT_LE16(counter_le, counter);
		if (plen >= mac_len) {
			if (func(key, key_len, 4, addr, len, &buf[pos]) < 0) {
				ret = -1;
				goto out;
			}
			pos += mac_len;
		} else {
			if (func(key, key_len, 4, addr, len, hash) < 0) {
				ret = -1;
				goto out;
			}
			memcpy(&buf[pos], hash, plen);
			pos += plen;
			break;
		}
		counter++;
	}

	/*
	 * Mask out unused bits in the last octet if it does not use all the
	 * bits.
	 */
	if (buf_len_bits % 8) {
		unsigned char mask = 0xff << (8 - buf_len_bits % 8);
		buf[pos - 1] &= mask;
	}

	ret = 0;
out:
	memset(hash, 0, mac_len);
	free(hash);
	return ret;
}

static const unsigned char nan_key[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};

static unsigned char nan_addrs[][ETH_ALEN] = {
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	},
	{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	},
};

static unsigned char nan_nonce[][NAN_NONCE_LEN] = {
	{
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	},
	{
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	},
};

static struct ieee80211_nan_ptk nan_ptk_128 = {
	.kck =	{
		0x67, 0x40, 0x47, 0x6f, 0x9c, 0xb4, 0xcd, 0xee,
		0xfb, 0xc7, 0xad, 0x25, 0x78, 0xd5, 0x5e, 0xb2,
	},
	.kek = {
		0xe5, 0xc7, 0x55, 0xbb, 0x4e, 0x4f, 0xd7, 0xbb,
		0xdb, 0x19, 0xa5, 0xb3, 0x6c, 0xcc, 0x77, 0xe3,
	},
	.tk = {
		0xe2, 0x7f, 0xfc, 0x7b, 0xa2, 0xd6, 0xb2, 0x44,
		0x63, 0x4a, 0x0c, 0xf2, 0x09, 0xf8, 0x06, 0x9a,
	},
	.kck_len = 16,
	.kek_len = 16,
	.tk_len = 16,
};

static struct ieee80211_nan_ptk nan_ptk_256 = {
	.kck =	{
		0x72, 0x70, 0xd5, 0xdc, 0x05, 0x44, 0x8a, 0xb4,
		0x1a, 0x73, 0xe5, 0x51, 0x56, 0xa0, 0x78, 0x3a,
		0x33, 0x74, 0x62, 0x4e, 0x81, 0xe0, 0x39, 0xf8,
	},
	.kek = {
		0x55, 0x3e, 0x2c, 0x8a, 0x0b, 0xab, 0xfc, 0xe1,
		0xf9, 0x45, 0xfb, 0xa7, 0xa6, 0xc9, 0x0c, 0x77,
		0x76, 0x64, 0x6b, 0xaa, 0xc0, 0x59, 0x7c, 0xd6,
		0xa4, 0x99, 0x31, 0xf2, 0x6e, 0xbf, 0x0e, 0x49,
	},
	.tk = {
		0x44, 0x61, 0x12, 0xba, 0x4c, 0x25, 0x8b, 0xe5,
		0x29, 0x33, 0x8f, 0x77, 0x45, 0x55, 0x13, 0x87,
		0x69, 0x61, 0xf4, 0x33, 0xad, 0x87, 0x47, 0xbb,
		0xa1, 0xd6, 0x5b, 0x4d, 0xaf, 0x0a, 0x37, 0x5a
	},
	.kck_len = 24,
	.kek_len = 32,
	.tk_len = 32,
};

static unsigned char nan_service_id[NL80211_NAN_FUNC_SERVICE_ID_LEN] = {
	0x48, 0xda, 0x63, 0xdc, 0xde, 0x19,
 };

static unsigned char nan_pmkid_128[NL80211_NAN_PMKID_LEN] = {
	0xcf, 0x4f, 0x64, 0x44, 0xd8, 0xe2, 0xc4, 0xef,
	0xa4, 0xf3, 0xa6, 0x51, 0xf3, 0x0f, 0x63, 0x4f
};

static unsigned char nan_pmkid_256[NL80211_NAN_PMKID_LEN] = {
	0x08, 0x11, 0x23, 0xc8, 0x57, 0x52, 0x6a, 0x09,
	0x6d, 0x46, 0x48, 0x2b, 0xa8, 0x02, 0xfc, 0x28
};

static unsigned char nan_sha256_digest[SHA256_MAC_LEN] = {
	0xde, 0x7a, 0xa9, 0x34, 0x0d, 0x1d, 0xbb, 0x73,
	0x4d, 0x4d, 0x5a, 0xcb, 0x6b, 0xe4, 0xed, 0xc9,
	0x0a, 0x16, 0x37, 0xaa, 0x1e, 0x5a, 0x34, 0x2e,
	0x58, 0xdd, 0x0b, 0x30, 0x4b, 0xa4, 0x8c, 0x32,
};

static unsigned char nan_sha384_digest[SHA384_MAC_LEN] = {
	0xb1, 0xf9, 0x75, 0xbd, 0x80, 0x84, 0x21, 0x35,
	0xc2, 0x38, 0xf7, 0x0d, 0x03, 0x32, 0x38, 0xe7,
	0xbb, 0x55, 0x39, 0x21, 0xf5, 0xb3, 0xbd, 0x5c,
	0x93, 0x78, 0x52, 0x61, 0x6f, 0x83, 0x58, 0x2d,
	0xdc, 0x0d, 0xe2, 0x25, 0x5e, 0x72, 0x6c, 0x95,
	0xd0, 0xcb, 0x09, 0xef, 0x2a, 0x8f, 0x08, 0x17,
};

void nan_verify_pmk(void)
{
	const EVP_MD *type;
	unsigned char data[2 * ETH_ALEN + 2 * WLAN_NAN_NONCE_LEN];
	unsigned char tmp[NAN_KCK_MAX_LEN + NAN_KEK_MAX_LEN + NAN_TK_MAX_LEN];
	unsigned char *pos = data;
	struct ieee80211_nan_ptk ptk = {};
	size_t total_len;
	int ret;

	memcpy(pos, nan_addrs[0], ETH_ALEN);
	pos += ETH_ALEN;

	memcpy(pos, nan_addrs[1], ETH_ALEN);
	pos += ETH_ALEN;

	memcpy(pos, nan_nonce[0], NAN_NONCE_LEN);
	pos += NAN_NONCE_LEN;

	memcpy(pos, nan_nonce[1], NAN_NONCE_LEN);
	pos += NAN_NONCE_LEN;

	type = EVP_sha256();
	ptk.kck_len = 16;
	ptk.kek_len = 16;
	ptk.tk_len = 16;
	total_len = ptk.kck_len + ptk.kek_len + ptk.tk_len;

	ret = nan_kdf(type, nan_key, sizeof(nan_key),
		      NAN_PTK_LABEL, data, sizeof(data),
		      tmp, total_len * 8);

	if (ret) {
		printf("Failed to calculate PTK for CS-128\n");
		exit(1);
	}

	memcpy(ptk.kck, tmp, ptk.kck_len);
	memcpy(ptk.kek, tmp + ptk.kck_len, ptk.kek_len);
	memcpy(ptk.tk, tmp + ptk.kck_len + ptk.kek_len, ptk.tk_len);

	if (memcmp(&ptk, &nan_ptk_128, total_len)) {
		printf("Bad PTK for CS-128\n");
		exit(1);
	}

	type = EVP_sha384();
	ptk.kck_len = 24;
	ptk.kek_len = 32;
	ptk.tk_len = 32;
	total_len = ptk.kck_len + ptk.kek_len + ptk.tk_len;

	ret = nan_kdf(type, nan_key, sizeof(nan_key),
		      NAN_PTK_LABEL, data, sizeof(data),
		      tmp, total_len * 8);

	if (ret) {
		printf("Failed to calculate PTK for CS-256\n");
		exit(1);
	}

	memcpy(ptk.kck, tmp, ptk.kck_len);
	memcpy(ptk.kek, tmp + ptk.kck_len, ptk.kek_len);
	memcpy(ptk.tk, tmp + ptk.kck_len + ptk.kek_len, ptk.tk_len);
	if (memcmp(&ptk, &nan_ptk_256, total_len)) {
		printf("Bad PTK for CS-256\n");
		exit(1);
	}
}

void nan_verify_pmkid(void)
{
	const unsigned char *addr[4];
	size_t lens[4];
	int ret;
	unsigned char digest[SHA384_MAC_LEN];

	addr[0] = (unsigned char *)NAN_PMKID_LABEL;
	lens[0] = strlen(NAN_PMKID_LABEL);
	addr[1] = nan_addrs[0];
	lens[1] = ETH_ALEN;
	addr[2] = nan_addrs[1];
	lens[2] = ETH_ALEN;
	addr[3] = nan_service_id;
	lens[3] = 6;

	ret = hmac_sha256_vector(nan_key, sizeof(nan_key), 4, addr,
				 lens, digest);
	if (ret) {
		printf("Failed to calculate pmkid for CS-128\n");
		exit(1);
	}

	if (memcmp(nan_pmkid_128, digest, NL80211_NAN_PMKID_LEN)) {
		printf("Bad PMKID for CS-128\n");
		exit(1);
	}

	memset(digest, 0, sizeof(digest));

	ret = hmac_sha384_vector(nan_key, sizeof(nan_key), 4, addr,
				 lens, digest);
	if (ret) {
		printf("Failed to calculate pmkid for CS-256\n");
		exit(1);
	}

	if (memcmp(nan_pmkid_256, digest, NL80211_NAN_PMKID_LEN)) {
		printf("Bad PMKID for CS-256\n");
		exit(1);
	}
}

void nan_verify_sha(void)
{
	unsigned char digest[SHA384_MAC_LEN] = {};
	const unsigned char *data = nan_nonce[0];
	size_t data_len = sizeof(nan_nonce[0]);
	int ret;

	ret = hmac_sha256_vector(nan_key, sizeof(nan_key), 1, &data, &data_len,
				 digest);
	if (ret) {
		printf("Failed to calculate digest for CS-128\n");
		exit(1);
	}

	if (memcmp(nan_sha256_digest, digest, SHA256_MAC_LEN)) {
		printf("Bad sha256 digest\n");
		exit(1);
	}

	memset(digest, 0, sizeof(digest));

	ret = hmac_sha384_vector(nan_key, sizeof(nan_key), 1, &data, &data_len,
				 digest);
	if (ret) {
		printf("Failed to calculate digest for CS-256\n");
		exit(1);
	}

	if (memcmp(nan_sha384_digest, digest, SHA256_MAC_LEN)) {
		printf("Bad sha384 digest\n");
		exit(1);
	}
}

void nan_verify(void)
{
	nan_verify_pmk();
	nan_verify_pmkid();
	nan_verify_sha();
}

void help(void)
{
	printf("NAN security function options: \n");
	printf("- verify\n");
	printf("- ptk <SK-128|SK-256> PMK <iaddr> <raddr> <inonce> <rnonce>\n");
	printf("- pmkid <SK-128|SK-256> PMK <iaddr> <raddr> <serv ID>\n");
}

int nan_sec_test(int argc, char **argv)
{
	int ret;

	if (argc < 1)
		return -EINVAL;

	if (strcmp(argv[0], "verify") == 0) {
		nan_verify();
		return 0;
	} else if (strcmp(argv[0], "help") == 0) {
		help();
		return 0;
	} else if (strcmp(argv[0], "ptk") == 0) {
		const EVP_MD *type;
		unsigned char pmk[NL80211_NAN_PMK_LEN];
		unsigned char data[2 * ETH_ALEN + 2 * WLAN_NAN_NONCE_LEN];
		unsigned char *pos = data;
		struct ieee80211_nan_ptk ptk = {};
		size_t total_len;

		argv++;
		argc--;

		if (argc != 6)
			return -EINVAL;

		if (strcmp("SK-128", argv[0]) == 0) {
			type = EVP_sha256();
			ptk.kck_len = 16;
			ptk.kek_len = 16;
			ptk.tk_len = 16;
		} else if (strcmp("SK-256", argv[0]) == 0) {
			type = EVP_sha384();
			ptk.kck_len = 24;
			ptk.kek_len = 32;
			ptk.tk_len = 32;
		} else
			return -EINVAL;

		total_len = ptk.kck_len + ptk.kek_len + ptk.tk_len;

		argv++;
		argc--;

		/* PMK */
		if (strlen(argv[0]) != (sizeof(pmk) * 2) ||
		    !hex2bin(argv[0], (char *)pmk))
			return -EINVAL;

		argv++;
		argc--;

		/* initiator address */
		if (mac_addr_a2n(pos, argv[0]) < 0)
			return -EINVAL;

		argv++;
		argc--;
		pos += ETH_ALEN;

		/* responder address */
		if (mac_addr_a2n(pos, argv[0]) < 0)
			return -EINVAL;

		argv++;
		argc--;
		pos += ETH_ALEN;

		/* initiator nonce */
		if (strlen(argv[0]) != (WLAN_NAN_NONCE_LEN * 2) ||
		    !hex2bin(argv[0], (char *)pos))
			return -EINVAL;

		argv++;
		argc--;
		pos += WLAN_NAN_NONCE_LEN;

		/* responder nonce */
		if (strlen(argv[0]) != (WLAN_NAN_NONCE_LEN * 2) ||
		    !hex2bin(argv[0], (char *)pos))
			return -EINVAL;

		argv++;
		argc--;

		ret = nan_kdf(type, pmk, sizeof(pmk),
			      NAN_PTK_LABEL, data, sizeof(data),
			      (unsigned char *)&ptk, total_len * 8);

		if (ret)
			printf("Failed to calculate PTK\n");
		else
			iw_hexdump("ptk", (unsigned char *)&ptk, total_len);
	} else if (strcmp(argv[0], "pmkid") == 0) {
		const EVP_MD *type;
		unsigned char pmk[NL80211_NAN_PMK_LEN];
		unsigned char iaddr[ETH_ALEN];
		unsigned char raddr[ETH_ALEN];
		unsigned char serv_id[6];
		unsigned char pmkid[NL80211_NAN_PMKID_LEN];
		const unsigned char *addr[4];
		size_t lens[4];

		argv++;
		argc--;

		if (argc != 5)
			return -EINVAL;

		if (strcmp("SK-128", argv[0]) == 0) {
			type = EVP_sha256();
		} else if (strcmp("SK-256", argv[0]) == 0) {
			type = EVP_sha384();
		} else
			return -EINVAL;

		argv++;
		argc--;

		/* PMK */
		if (strlen(argv[0]) != (sizeof(pmk) * 2) ||
		    !hex2bin(argv[0], (char *)pmk))
			return -EINVAL;

		argv++;
		argc--;

		/* initiator address */
		if (mac_addr_a2n(iaddr, argv[0]) < 0)
			return -EINVAL;

		argv++;
		argc--;

		/* responder address */
		if (mac_addr_a2n(raddr, argv[0]) < 0)
			return -EINVAL;

		argv++;
		argc--;

		/* service ID */
		if (strlen(argv[0]) != (6 * 2) ||
		    !hex2bin(argv[0], (char *)serv_id))
			return -EINVAL;

		addr[0] = (unsigned char *)NAN_PMKID_LABEL;
		lens[0] = strlen(NAN_PMKID_LABEL);
		addr[1] = iaddr;
		lens[1] = ETH_ALEN;
		addr[2] = raddr;
		lens[2] = ETH_ALEN;
		addr[3] = serv_id;
		lens[3] = 6;

		if (type == EVP_sha256())
			ret = hmac_sha256_vector(pmk, sizeof(pmk), 4, addr,
						 lens, pmkid);
		else
			ret = hmac_sha384_vector(pmk, sizeof(pmk), 4, addr,
						 lens, pmkid);

		if (ret)
			printf("Failed to calculate PMKID\n");
		else
			iw_hexdump("pmkid", pmkid, NL80211_NAN_PMKID_LEN);
	} else {
			printf("Invalid test request: %s\n", *argv);
			help();
			return -EINVAL;
	}

	return ret;
}
