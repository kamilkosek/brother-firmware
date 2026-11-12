#include "web_request.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char body[] = "cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99";
static enum cfw_request_result run(const char *text, struct cfw_level_request *out)
{
    return cfw_validate_level_request("POST", 1, "http://192.0.2.1",
        "192.0.2.1", "application/x-www-form-urlencoded;charset=UTF-8",
        (const unsigned char *)text, strlen(text), out);
}

int main(void)
{
    struct cfw_level_request out = {{11,22,33,44},15,0,{0,0,0,0},0};
    struct cfw_level_request sentinel;
    const char *bad[] = {
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=101&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=-1&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=1.5&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=1e2&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99&cfw_m=1",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99&B518=1",
        "cfw_action=set_levels&cfw_confirm=0&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=%00&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=%ff&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=%3&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=+5&cfw_y=0&cfw_c=37&cfw_m=99",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99&",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99&cfw%5fm=2",
        "cfw_action=set_levels&cfw_confirm=1&cfw_bk=1000000000000&cfw_y=0&cfw_c=37&cfw_m=99",
        "", "&", "cfw_action", "=set_levels", "cfw_action=%gg", NULL
    };
    const char *origins[] = {NULL, "", "null", "http://evil.example", "https://192.0.2.1",
        "http://192.0.2.1.evil.example", "http://evil@192.0.2.1",
        "http://192.0.2.1/", "http://192.0.2.1:81", NULL};
    size_t i, cut;
    assert(run(body, &out) == CFW_REQUEST_OK);
    assert(out.remaining[0] == 100 && out.remaining[1] == 0 &&
        out.remaining[2] == 37 && out.remaining[3] == 99);
    sentinel = out;
    assert(run("cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99&cfw_mask=8&cfw_expect_m=1099511627775",&out)==CFW_REQUEST_OK);
    assert(out.selected_mask==8 && out.mask_explicit && out.expected_mask==8 && out.expected_total[3]==UINT64_C(0xffffffffff));
    assert(run("cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99&cfw_mask=0",&out)==CFW_REQUEST_FIELDS);
    assert(run("cfw_action=set_levels&cfw_confirm=1&cfw_bk=100&cfw_y=0&cfw_c=37&cfw_m=99&cfw_expect_m=1099511627776",&out)==CFW_REQUEST_FIELDS);
    out=sentinel;
    for (i = 0; bad[i]; ++i) {
        assert(run(bad[i], &out) != CFW_REQUEST_OK);
        assert(memcmp(&out, &sentinel, sizeof out) == 0);
    }
    for (i = 0; i < sizeof origins / sizeof origins[0]; ++i) {
        assert(cfw_validate_level_request("POST",1,origins[i],"192.0.2.1",
            "application/x-www-form-urlencoded",(const unsigned char *)body,
            strlen(body),&out) == CFW_REQUEST_ORIGIN);
        assert(memcmp(&out,&sentinel,sizeof out) == 0);
    }
    assert(cfw_validate_level_request("GET",1,"http://192.0.2.1","192.0.2.1",
        "application/x-www-form-urlencoded",(const unsigned char *)body,strlen(body),&out)
        == CFW_REQUEST_METHOD);
    assert(cfw_validate_level_request("POST",0,"http://192.0.2.1","192.0.2.1",
        "application/x-www-form-urlencoded",(const unsigned char *)body,strlen(body),&out)
        == CFW_REQUEST_LOGIN);
    assert(cfw_validate_level_request("POST",-1,NULL,NULL,NULL,NULL,0,&out) == CFW_REQUEST_LOGIN);
    assert(cfw_validate_level_request("POST",1,"http://printer.local:8080","PRINTER.LOCAL:8080",
        "Application/X-Www-Form-Urlencoded; charset=utf-8",(const unsigned char *)body,strlen(body),&out)
        == CFW_REQUEST_OK);
    assert(cfw_validate_level_request("POST",1,"http://192.0.2.1","192.0.2.1",
        "application/json",(const unsigned char *)body,strlen(body),&out) == CFW_REQUEST_TYPE);
    assert(cfw_validate_level_request("POST",1,"http://192.0.2.1","192.0.2.1",
        "application/x-www-form-urlencoded",(const unsigned char *)body,1025,&out) == CFW_REQUEST_BODY);
    assert(run("cfw_action=set_levels&cfw_confirm=1&cfw_bk=%31%30%30&cfw_y=0&cfw_c=37&cfw_m=99",&out)
        == CFW_REQUEST_OK);
    /* Every prefix before the last field is present must fail atomically. */
    sentinel = out;
    for (cut = 0; cut < (size_t)(strstr(body,"&cfw_m=")-body)+7; ++cut) {
        assert(cfw_validate_level_request("POST",1,"http://192.0.2.1","192.0.2.1",
            "application/x-www-form-urlencoded",(const unsigned char *)body,cut,&out) != CFW_REQUEST_OK);
        assert(memcmp(&out,&sentinel,sizeof out) == 0);
    }
    puts("web request: auth, method, origin, field, encoding, bounds and atomic-output checks passed");
    return 0;
}
