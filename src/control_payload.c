/* Exact R2401191337 custom control UI. Upload performed by the user. */
#include <stdint.h>
#include <stddef.h>
#include "web_request.h"
#include "native_level_model.h"
#include "native_backend.h"

typedef int (*output_fn)(uint32_t,const char *);
typedef int (*env_fn)(uint32_t,const char *,char *,uint32_t);
typedef int (*auth_fn)(uint32_t,int *);
typedef const char *(*header_fn)(uint32_t,const char *);
typedef int (*render_fn)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
typedef int (*param_fn)(unsigned,unsigned,char *,unsigned);

static void emit(uint32_t c,const char *s)
{ ((output_fn)(uintptr_t)0x40643033)(c,s); }

static void number(uint32_t c,uint64_t value)
{
    char text[24];
    unsigned used = sizeof text-1;
    text[used] = 0;
    do { text[--used] = (char)('0'+value%10); value /= 10; } while (value);
    emit(c,text+used);
}

static int length(const char *s,size_t *out)
{
    size_t n=0,i;
    if (!s || !*s) return 0;
    for (i=0;s[i];++i) {
        if (i>=4 || s[i]<'0' || s[i]>'9') return 0;
        n=n*10+(unsigned)(s[i]-'0');
        if(n>1024) return 0;
    }
    if (!n) return 0;
    *out=n;
    return 1;
}

static const char *header(uint32_t context,const char *name)
{
    const uint32_t *request=(const uint32_t *)(uintptr_t)context;
    const uint32_t *unit,*http;
    if(!request || request[0]!=0x013106c1 || !request[8]) return NULL;
    unit=(const uint32_t *)(uintptr_t)request[8];
    if(!unit[11]) return NULL;
    http=(const uint32_t *)(uintptr_t)unit[11];
    return ((header_fn)(uintptr_t)0x40751e75)(http[18],name);
}

static const unsigned char *body(uint32_t context)
{
    const uint32_t *request=(const uint32_t *)(uintptr_t)context;
    const uint32_t *unit,*http;
    if(!request || request[0]!=0x013106c1 || !request[8]) return NULL;
    unit=(const uint32_t *)(uintptr_t)request[8];
    if(!unit[11]) return NULL;
    http=(const uint32_t *)(uintptr_t)unit[11];
    return (const unsigned char *)(uintptr_t)http[19];
}

int cfw_status_renderer(uint32_t context,uint32_t p2,uint32_t p3,uint32_t p4,uint32_t p5)
{
    static const char *const names[4]={"Black","Yellow","Cyan","Magenta"};
    static const char *const fields[4]={"cfw_bk","cfw_y","cfw_c","cfw_m"};
    static const char *const expected[4]={"cfw_expect_bk","cfw_expect_y","cfw_expect_c","cfw_expect_m"};
    struct cfw_native_level current[4];
    struct cfw_level_request desired;
    char method[16]={0};
    unsigned char shown[4]={0,0,0,0};
    char native[16];
    size_t n=0;
    unsigned i;
    int logged=0,got_method;
    enum cfw_request_result result=CFW_REQUEST_METHOD;
    enum cfw_save_result saved=CFW_SAVE_INVALID;
    int attempted=0;
    if(((auth_fn)(uintptr_t)0x4072acb5)(context,&logged)!=0) logged=0;
    got_method=((env_fn)(uintptr_t)0x4072a65d)(context,"REQUEST_METHOD",method,sizeof method);
    if(logged==1 && got_method==0 && method[0]=='P') {
        if(length(header(context,"Content-Length"),&n))
            result=cfw_validate_level_request(method,logged,header(context,"Origin"),
                header(context,"Host"),header(context,"Content-Type"),body(context),n,&desired);
        else result=CFW_REQUEST_BODY;
        if(result==CFW_REQUEST_OK) { attempted=1;saved=cfw_save_level(&desired); }
    }
    /* Render the original bars after committing so they read the new state. */
    ((render_fn)(uintptr_t)0x406ef197)(context,p2,p3,p4,p5);
    emit(context,"<section style=\"margin:20px;padding:16px;border:2px solid #15498b;background:#fff\"><h2>CUSTOM FW 0.3</h2><p>Ink levels are calculated from consumption counters. The optical low-ink sensor no longer determines the low-ink state.</p>");
    if(logged!=1) {emit(context,"<p>Sign in above to change ink levels.</p></section>");return 0;}
    if(attempted) {
        static const char *const messages[]={
            "Saved and read back. The native level display was verified.",
            "Printer or access is busy. Nothing changed; try again while idle.",
            "Counters changed since this page was loaded. Reload the page and try again.",
            "Select exactly one color and a target from 1 to 100.",
            "A cartridge, empty, or blocking condition is active. It was not overridden; nothing was saved.",
            "Storage verification failed. No change was confirmed; previous values were restored if a write occurred.",
            "ERROR: Restoration could not be fully verified. Inspect the values before making any further changes."
        };
        emit(context,"<p><strong>");emit(context,messages[(unsigned)saved<7 ? saved : CFW_SAVE_INVALID]);emit(context,"</strong></p>");
    } else if(got_method==0 && method[0]=='P') {
        emit(context,"<p><strong>Request rejected (code ");number(context,(unsigned)result);emit(context,"). Nothing was saved.</strong></p>");
    }
    emit(context,"<p>Calibrate only the cartridge you have checked. 100% means newly full; the minimum target is 1%. Cartridge faults remain separate.</p><form method=post action=\"/general/status.html\"><input type=hidden name=cfw_action value=set_levels><table><tr><th>Color</th><th>Total consumption</th><th>Sensor counter</th><th>Calculation</th><th>Target %</th><th>Action</th></tr>");
    for(i=0;i<4;++i) {
        unsigned j,value=0;
        if(!cfw_read_state(i,&current[i])) {emit(context,"</table></form><p>Cannot read counters. Please reload.</p></section>");return 0;}
        emit(context,"<input type=hidden name=\"");emit(context,expected[i]);emit(context,"\" value=\"");number(context,current[i].total);emit(context,"\">");
        for(j=0;j<sizeof native;++j) native[j]=0;
        if(((param_fn)(uintptr_t)0x4065ace9)(0,0xac+i,native,sizeof native)==0) {
            for(j=0;j<sizeof native && native[j]>='0' && native[j]<='9';++j)
                value=value*10u+(unsigned)(native[j]-'0');
        }
        if(value>100) value=0;
        shown[i]=(unsigned char)value;
        emit(context,"<tr><td>");emit(context,names[i]);emit(context,"</td><td>");number(context,current[i].total);
        emit(context,"</td><td>");number(context,current[i].sensor);emit(context,"</td><td>");
        emit(context,current[i].gated_empty ? "Empty/blocking flag" : (current[i].near ? "Sensor / low ink" : "Total consumption"));
        emit(context,"</td><td><input type=number min=0 max=100 name=\"");emit(context,fields[i]);emit(context,"\" value=\"");number(context,shown[i]);emit(context,"\"></td><td><button type=submit name=cfw_mask value=\"");number(context,1u<<i);emit(context,"\">Save</button></td></tr>");
    }
    emit(context,"</table><label><input type=checkbox name=cfw_confirm value=1 required> I have checked the actual ink level.</label></form><p><a href=\"/general/status.html\">Reload status page</a></p>");
    emit(context,"</section>");
    return 0;
}
