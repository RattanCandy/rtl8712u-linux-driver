from pathlib import Path
s = Path("ieee80211.c").read_text()
fn = s[s.index("u8 *r8712_get_ie("):s.index("\nstatic void set_supported_rate(",s.index("u8 *r8712_get_ie("))]
base = Path("tests/parser_test.c").read_text().replace("int main(void)", "int baseline_main(void)", 1)
extra = r'''
typedef int sint;
typedef unsigned int uint;
'''
extra += fn
s = Path('rtl871x_mlme.c').read_text()
wmm = s[s.index('int r8712_restruct_wmm_ie('):s.index('\n/*\n * Ported from 8185:',s.index('int r8712_restruct_wmm_ie('))]
extra += '\n' + wmm
extra += r'''
int main(void)
{
    int baseline = baseline_main();
    struct _adapter a = {0};
    u8 out[MAX_IE_SZ] = {0};
    static const u8 ccmp[] = {0,15,172,4};
    static const u8 psk[] = {0,15,172,2};
    static const u8 sae[] = {0,15,172,8};
    u8 rsn[100] = {0};
    int n;
    uint elen;
    u8 ie_stream[] = {1,2,0xaa,0xbb,45,1,0xcc,48,2,0x01,0x00};
    check(r8712_get_ie(ie_stream,48,&elen,sizeof(ie_stream)) == ie_stream + 7 && elen == 2, "IE scanner locates valid element");
    check(r8712_get_ie(ie_stream,48,&elen,8) == NULL && elen == 0, "IE scanner rejects partial header");
    check(r8712_get_ie(ie_stream,48,&elen,9) == NULL, "IE scanner rejects truncated payload");
    check(r8712_get_ie(ie_stream,48,&elen,0) == NULL, "IE scanner rejects zero length");
    u8 malformed[] = {1,255};
    check(r8712_get_ie(malformed,1,&elen,2) == NULL, "IE scanner rejects oversized element");
    u8 zero[] = {4,0,6,0};
    check(r8712_get_ie(zero,6,&elen,4) == zero+2, "IE scanner accepts zero-length element");
    /* WMM input: 12 fixed bytes, vendor IE (dd 07 OUI,type,subtype). */
    u8 wmm[21] = {0};
    wmm[12]=0xdd; wmm[13]=7;
    wmm[14]=0;wmm[15]=0x50;wmm[16]=0xf2;wmm[17]=2;
    wmm[18]=0;wmm[19]=1;wmm[20]=0;
    memset(out,0,sizeof(out));
    check(r8712_restruct_wmm_ie(&a,wmm,out,sizeof(wmm),34)==43 &&
          out[34]==0xdd && out[35]==7 && out[40]==0,
          "WMM IE appends exactly 9 validated bytes");
    check(r8712_restruct_wmm_ie(&a,wmm,out,20,34)==34,
          "Truncated WMM IE rejected");
    check(r8712_restruct_wmm_ie(&a,wmm,out,sizeof(wmm),MAX_IE_SZ-8)==MAX_IE_SZ-8,
          "WMM output capacity enforced");
    /* Build variable-size RSN: group CCMP, pairwise TKIP+CCMP, SAE+PSK. */
    int off=12;
    rsn[off++]=0x30;
    rsn[off++]=0;
    rsn[off++]=1; rsn[off++]=0;
    memcpy(rsn+off,ccmp,4);off+=4;
    rsn[off++]=2;rsn[off++]=0;
    memcpy(rsn+off,ccmp,4); rsn[off+3]=2;off+=4;
    memcpy(rsn+off,ccmp,4);off+=4;
    rsn[off++]=2;rsn[off++]=0;
    memcpy(rsn+off,sae,4);off+=4;
    memcpy(rsn+off,psk,4);off+=4;
    rsn[off++]=0x80;rsn[off++]=0;
    rsn[13]=off-14;
    n=r8712_build_wpa2_psk_ie(&a,rsn,out,off);
    check(n==34 && !memcmp(out+28,psk,4) && !memcmp(out+22,ccmp,4) && out[32]==0,
      "Variable suites select CCMP/PSK and clear optional PMF");
    /* Optional zero PMKID count plus group-management cipher. */
    rsn[off++]=0;rsn[off++]=0;
    memcpy(rsn+off,ccmp,4);off+=4;
    rsn[13]=off-14;
    check(r8712_build_wpa2_psk_ie(&a,rsn,out,off)==34,
      "Optional PMKID count and group management parsed");
    /* Reject invalid PMKID length. */
    rsn[off-6]=1;
    check(r8712_build_wpa2_psk_ie(&a,rsn,out,off)==0,
      "Truncated PMKID rejected");
    rsn[off-6]=0;
    /* Reject an extra byte after optional suites. */
    rsn[off++]=0xff;rsn[13]=off-14;
    check(r8712_build_wpa2_psk_ie(&a,rsn,out,off)==0,
      "Trailing malformed byte rejected");
    check(baseline==0 && failures==0, "All extended regressions");
    printf("Extended failures: %d\n",failures);
    return failures ? 1 : 0;
}
'''
Path("tests/extended_test.c").write_text(base+"\n"+extra)
print("Generated extended tests from real driver functions")
