from pathlib import Path

source = Path("rtl871x_mlme.c").read_text()
start = source.index("static int r8712_build_wpa2_psk_ie(")
end = source.index("\nsint r8712_restruct_sec_ie(", start)

helper = source[start:end]

prefix = r'''
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
'''

tests = r'''
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
'''

Path("tests/parser_test.c").write_text(
    prefix + helper + "\n" + tests
)

print("Actual driver parser extracted into tests/parser_test.c")
