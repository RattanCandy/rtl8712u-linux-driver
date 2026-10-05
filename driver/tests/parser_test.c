
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef uint8_t u8;
#define MAX_IE_SZ 768
#define _AES_ 4

struct pmkid_entry {
    u8 PMKID[16];
};

struct security_priv {
    int XGrpPrivacy;
    struct pmkid_entry PMKIDList[16];
};

struct mlme_priv {
    u8 assoc_bssid[6];
};

struct _adapter {
    struct security_priv securitypriv;
    struct mlme_priv mlmepriv;
};

static int cached_entry = -1;

static int SecIsInPMKIDList(struct _adapter *a, u8 *bssid)
{
    (void)a;
    (void)bssid;
    return cached_entry;
}
static int r8712_build_wpa2_psk_ie(struct _adapter *adapter,
				  const u8 *in, u8 *out,
				  unsigned int in_len)
{
	static const u8 ccmp[4] = {0x00, 0x0f, 0xac, 0x04};
	static const u8 psk[4] = {0x00, 0x0f, 0xac, 0x02};
	const u8 *ie = NULL, *p, *end;
	u8 caps[2] = {0, 0};
	unsigned int pos, len, count, i;
	bool pairwise_ok, akm_ok;
	int entry;
	struct security_priv *sec = &adapter->securitypriv;

	if (!in || !out || in_len < 12 || in_len > MAX_IE_SZ)
		return 0;

	/* Find and validate the complete RSN element. */
	for (pos = 12; pos < in_len; pos += len) {
		if (in_len - pos < 2)
			return 0;

		len = (unsigned int)in[pos + 1] + 2;
		if (len > in_len - pos)
			return 0;

		if (in[pos] == 0x30) {
			ie = in + pos;
			break;
		}
	}
	if (!ie)
		return 0;

	p = ie + 2;
	end = ie + ie[1] + 2;

	/* Version and group cipher. */
	if (end - p < 8 || p[0] != 1 || p[1] != 0)
		return 0;
	p += 2;

	if (memcmp(p, ccmp, 4))
		return 0;
	p += 4;

	/* Pairwise cipher list. */
	if (end - p < 2)
		return 0;
	count = p[0] | ((unsigned int)p[1] << 8);
	p += 2;
	if (!count || count > (unsigned int)(end - p) / 4)
		return 0;

	pairwise_ok = false;
	for (i = 0; i < count; i++) {
		if (!memcmp(p + i * 4, ccmp, 4))
			pairwise_ok = true;
	}
	p += count * 4;

	if (!pairwise_ok || end - p < 2)
		return 0;

	/* Authentication/key-management list. */
	count = p[0] | ((unsigned int)p[1] << 8);
	p += 2;
	if (!count || count > (unsigned int)(end - p) / 4)
		return 0;

	akm_ok = false;
	for (i = 0; i < count; i++) {
		if (!memcmp(p + i * 4, psk, 4))
			akm_ok = true;
	}
	p += count * 4;

	if (!akm_ok)
		return 0;

	/* Optional RSN capabilities. */
	if (p < end) {
		if (end - p < 2)
			return 0;
		caps[0] = p[0];
		caps[1] = p[1];
		p += 2;
	}

	/* PMF required: this driver cannot satisfy it. */
	if (caps[0] & 0x40)
		return 0;

	/* Validate any advertised PMKID list. */
	if (p < end) {
		if (end - p < 2)
			return 0;
		count = p[0] | ((unsigned int)p[1] << 8);
		p += 2;
		if (count > (unsigned int)(end - p) / 16)
			return 0;
		p += count * 16;
	}

	/* Optional group-management cipher suite. */
	if (p < end) {
		if (end - p != 4)
			return 0;
		p += 4;
	}
	if (p != end)
		return 0;

	/* Preauthentication and PMF are not advertised. */
	caps[0] &= ~(u8)0xc1;

	/*
	 * Output: fixed fields + RSN:
	 * version, group CCMP, pairwise CCMP,
	 * AKM PSK, capabilities, optional cached PMKID.
	 */
	memcpy(out, in, 12);
	pos = 12;

	out[pos++] = 0x30;
	out[pos++] = 0; /* RSN element length */
	out[pos++] = 1;
	out[pos++] = 0;

	memcpy(out + pos, ccmp, 4);
	pos += 4;
	out[pos++] = 1;
	out[pos++] = 0;

	memcpy(out + pos, ccmp, 4);
	pos += 4;
	out[pos++] = 1;
	out[pos++] = 0;

	memcpy(out + pos, psk, 4);
	pos += 4;
	out[pos++] = caps[0];
	out[pos++] = caps[1];

	entry = SecIsInPMKIDList(adapter,
				 adapter->mlmepriv.assoc_bssid);
	if (entry >= 0) {
		out[pos++] = 1;
		out[pos++] = 0;
		memcpy(out + pos, sec->PMKIDList[entry].PMKID, 16);
		pos += 16;
	}

	out[13] = pos - 14;
	sec->XGrpPrivacy = _AES_;

	return pos;
}


static int failures;

static void check(bool ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

int main(void)
{
    struct _adapter adapter = {0};
    u8 output[MAX_IE_SZ] = {0};

    /* Captured WPA2-PSK + WPA3-SAE association input. */
    u8 mixed[] = {
        0x98,0x81,0x89,0x97,0x1d,0,0,0,0x64,0,0x11,0x15,
        0x30,0x18,0x01,0x00,0x00,0x0f,0xac,0x04,
        0x01,0x00,0x00,0x0f,0xac,0x04,
        0x02,0x00,0x00,0x0f,0xac,0x02,
        0x00,0x0f,0xac,0x08,0x00,0x00
    };

    const u8 expected[] = {
        0x98,0x81,0x89,0x97,0x1d,0,0,0,0x64,0,0x11,0x15,
        0x30,0x14,0x01,0x00,0x00,0x0f,0xac,0x04,
        0x01,0x00,0x00,0x0f,0xac,0x04,
        0x01,0x00,0x00,0x0f,0xac,0x02,0x00,0x00
    };

    int n = r8712_build_wpa2_psk_ie(
        &adapter, mixed, output, sizeof(mixed));

    check(n == sizeof(expected) &&
          memcmp(output, expected, sizeof(expected)) == 0,
          "Mixed PSK/SAE becomes valid WPA2-PSK");

    n = r8712_build_wpa2_psk_ie(
        &adapter, expected, output, sizeof(expected));
    check(n == sizeof(expected) &&
          memcmp(output, expected, sizeof(expected)) == 0,
          "WPA2-only preserved");

    for (unsigned int len = 0; len < sizeof(mixed); len++) {
        n = r8712_build_wpa2_psk_ie(
            &adapter, mixed, output, len);
        if (n != 0) {
            failures++;
            printf("FAIL: truncated length %u\n", len);
        }
    }
    check(n == 0, "Truncated input checks completed");

    u8 modified[sizeof(mixed)];
    memcpy(modified, mixed, sizeof(mixed));
    modified[13] = 255;
    check(r8712_build_wpa2_psk_ie(
          &adapter, modified, output, sizeof(modified)) == 0,
          "Invalid RSN element length rejected");

    memcpy(modified, mixed, sizeof(mixed));
    modified[36] = 0x40;
    check(r8712_build_wpa2_psk_ie(
          &adapter, modified, output, sizeof(modified)) == 0,
          "Mandatory PMF rejected");

    memcpy(modified, mixed, sizeof(mixed));
    modified[31] = 0x08;
    check(r8712_build_wpa2_psk_ie(
          &adapter, modified, output, sizeof(modified)) == 0,
          "SAE-only rejected");

    cached_entry = 0;
    n = r8712_build_wpa2_psk_ie(
        &adapter, mixed, output, sizeof(mixed));
    check(n == 52 && output[13] == 38,
          "Cached PMKID incorporated");
    cached_entry = -1;

    /* Fuzz malformed input lengths and bytes. */
    srand(8712);
    for (int i = 0; i < 5000; i++) {
        u8 input[MAX_IE_SZ];
        unsigned int len = rand() % (MAX_IE_SZ + 1);

        for (unsigned int j = 0; j < len; j++)
            input[j] = rand() & 255;

        n = r8712_build_wpa2_psk_ie(
            &adapter, input, output, len);

        if (n < 0 || n > MAX_IE_SZ) {
            failures++;
            break;
        }
    }
    check(n >= 0 && n <= MAX_IE_SZ,
          "Random malformed-input checks completed");

    printf("Failures: %d\n", failures);
    return failures ? 1 : 0;
}
