/* Exact R firmware binding. All writes remain behind the authenticated caller.
 * Serializes object clients and blocks native printer-resource acquisition
 * during each selected-color transaction. Not power-fail atomic. */
#include <stdint.h>
#include <stddef.h>
#include "native_backend.h"

#define BYTE(a) (*(volatile unsigned char *)(uintptr_t)(a))
#define WORD(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define QUAD(a) (*(volatile uint64_t *)(uintptr_t)(a))
typedef int (*handle_fn)(void);
typedef int (*io_fn)(int,void *,unsigned);
typedef uint32_t (*color_fn)(unsigned);
typedef int (*one_fn)(unsigned);
typedef void (*void_one_fn)(unsigned);
typedef void (*notify_fn)(void);
typedef void (*near_fn)(unsigned,unsigned);
typedef int (*lock_fn)(unsigned,unsigned,unsigned);
static int critical_enter(void)
{
    if(BYTE(0x41bf3605) || BYTE(0x41bf3606)) return 0;
    return ((handle_fn)(uintptr_t)0x400578e9)()==0;
}
static void critical_leave(void)
{ ((handle_fn)(uintptr_t)0x4044b765)(); }
static const unsigned colors[4]={0,0x11,0x12,0x13};
static const unsigned totals[4]={0x60,0x6a,0x65,0x6f};
static const unsigned sensors[4]={0x3c,0x44,0x40,0x48};
static const unsigned physical[4]={0,2,1,3};

static int io(unsigned cpu,unsigned address,unsigned count,unsigned char *data,unsigned write)
{
    uint32_t descriptor[2];
    int handle=((handle_fn)(uintptr_t)(cpu ? 0x403cc8a7 : 0x404b1b3b))();
    if(handle<1 || handle>0x51) return 0;
    descriptor[0]=cpu ? (address<<16)|count : (address<<24)|(count<<16);
    descriptor[1]=(uint32_t)(uintptr_t)data;
    return ((io_fn)(uintptr_t)(write ? 0x403c9d17 : 0x403c9ce5))(handle,descriptor,0)>=0;
}

static uint64_t decode(const unsigned char *b,unsigned n)
{
    uint64_t v=0;
    unsigned i;
    for(i=0;i<n;++i) v=(v<<8)|b[i];
    return v;
}

static void encode(unsigned char *b,unsigned n,uint64_t value)
{
    while(n) {b[--n]=(unsigned char)value;value>>=8;}
}

static int write_verified(unsigned cpu,unsigned address,unsigned n,unsigned char *value)
{
    unsigned char check[5];
    unsigned i;
    if(n>sizeof check || !io(cpu,address,n,value,1) || !io(cpu,address,n,check,0)) return 0;
    for(i=0;i<n;++i) if(check[i]!=value[i]) return 0;
    return 1;
}

static int masked_cpu(unsigned address,unsigned mask,unsigned selected)
{
    unsigned char current;
    if(!io(1,address,1,&current,0)) return 0;
    current=(unsigned char)((current&~mask)|(selected&mask));
    return write_verified(1,address,1,&current);
}

static int check_cpu(unsigned address,unsigned mask,unsigned selected)
{
    unsigned char current;
    return io(1,address,1,&current,0) && (current&mask)==(selected&mask);
}

int cfw_read_state(unsigned i,struct cfw_native_level *s)
{
    unsigned char raw[5];
    unsigned bit;
    if(!s || i>=4) return 0;
    bit=1u<<i;
    if(!io(0,totals[i],5,raw,0)) return 0;
    s->total=decode(raw,5);
    if(!io(0,sensors[i],4,raw,0)) return 0;
    s->sensor=(uint32_t)decode(raw,4);
    s->threshold=((color_fn)(uintptr_t)0x40283b4b)(colors[i]);
    s->low_threshold=((color_fn)(uintptr_t)0x40283ddf)(colors[i]);
    s->baseline=((color_fn)(uintptr_t)0x40282c49)(colors[i]) ? 0 :
        (i==0 ? 0x1198342b : 0x16c34499);
    s->near=(BYTE(0x41bfa7c5)&bit)!=0;
    s->gated_empty=((BYTE(0x41bfa7c1)&bit) || (BYTE(0x41bfa7cd)&(bit<<4)) ||
        (BYTE(0x41bfa8aa)&bit))!=0;
    return 1;
}

struct snapshot {
    uint64_t ram_total,pending;
    uint32_t ram_sensor;
    unsigned char total[5],sensor[4],latch,warning;
    unsigned char total_fraction,sensor_fraction,pending_fraction;
    unsigned char near,mirror,cache,empty,display;
};

static void restore_ram(unsigned i,const struct snapshot *old)
{
    unsigned bit=1u<<i,high=bit<<4;
    QUAD(0x42354e00+8*i)=old->ram_total;
    WORD(0x42354e88+4*i)=old->ram_sensor;
    QUAD(0x42354f58+8*i)=old->pending;
    BYTE(0x42354e20+i)=old->total_fraction;
    BYTE(0x42354e98+i)=old->sensor_fraction;
    BYTE(0x42354f78+i)=old->pending_fraction;
    BYTE(0x41bfa7c5)=(unsigned char)((BYTE(0x41bfa7c5)&~bit)|(old->near&bit));
    BYTE(0x41bede4f)=(unsigned char)((BYTE(0x41bede4f)&~high)|(old->mirror&high));
    BYTE(0x41bede20)=(unsigned char)((BYTE(0x41bede20)&~(1u<<physical[i]))|
        (old->cache&(1u<<physical[i])));
    BYTE(0x41bfa7c1)=(unsigned char)((BYTE(0x41bfa7c1)&~(bit|high))|(old->empty&(bit|high)));
    BYTE(0x41bfa7c6)=(unsigned char)((BYTE(0x41bfa7c6)&~high)|(old->display&high));
}

enum cfw_save_result cfw_save_level(const struct cfw_level_request *request)
{
    struct snapshot old;
    struct cfw_native_level current,plan;
    uint32_t mutex=WORD(0x41bf18e0);
    unsigned mask,i=0,bit,high,hardware_bit,pair;
    unsigned char next_total[5],next_sensor[4];
    enum cfw_save_result result=CFW_SAVE_INVALID;
    int reserved=0,ram_applied=0,dirty=0,rollback_ok;
    if(!request || !request->mask_explicit) return CFW_SAVE_INVALID;
    if(BYTE(0x41bf3605) || BYTE(0x41bf3606)) return CFW_SAVE_BUSY;
    mask=request->selected_mask;
    if(!mask || mask>8 || (mask&(mask-1))) return CFW_SAVE_INVALID;
    while((1u<<i)!=mask) ++i;
    if(!(request->expected_mask&mask)) return CFW_SAVE_INVALID;
    /* Try-lock only: no wait behind another object access or calibration. */
    if(!mutex || ((lock_fn)(uintptr_t)0x404214a5)(mutex,0,10)!=0) return CFW_SAVE_BUSY;
    result=CFW_SAVE_BUSY;
    if(BYTE(0x42195bff)!=0 || ((one_fn)(uintptr_t)0x403fadef)(3)!=0) goto finish;
    reserved=1;
    if(BYTE(0x42195bff)!=1) goto finish;
    if(!cfw_read_state(i,&current) || !io(0,totals[i],5,old.total,0) ||
       !io(0,sensors[i],4,old.sensor,0) || !io(1,0x6ab,1,&old.latch,0) ||
       !io(1,0x624,1,&old.warning,0)) {result=CFW_SAVE_IO_ROLLED_BACK;goto finish;}
    result=CFW_SAVE_STALE;
    if(current.total!=request->expected_total[i] || decode(old.total,5)!=current.total ||
       decode(old.sensor,4)!=current.sensor) goto finish;
    old.ram_total=QUAD(0x42354e00+8*i);
    old.ram_sensor=WORD(0x42354e88+4*i);
    if(old.ram_total!=current.total || old.ram_sensor!=current.sensor) goto finish;
    result=CFW_SAVE_DEVICE_FAULT;
    if(current.gated_empty) goto finish;
    result=CFW_SAVE_INVALID;
    if(cfw_calibration_plan(&current,request->remaining[i],&plan)!=CFW_NATIVE_OK) goto finish;
    /* A native first-cartridge history transition can remove the baseline.
     * 100% remains valid across it; partial targets require a stable branch. */
    if(current.baseline && current.near!=plan.near && request->remaining[i]!=100) goto finish;
    bit=1u<<i;high=bit<<4;hardware_bit=1u<<physical[i];pair=3u<<(2*physical[i]);
    old.pending=QUAD(0x42354f58+8*i);
    old.total_fraction=BYTE(0x42354e20+i);
    old.sensor_fraction=BYTE(0x42354e98+i);
    old.pending_fraction=BYTE(0x42354f78+i);
    old.near=BYTE(0x41bfa7c5);old.mirror=BYTE(0x41bede4f);old.cache=BYTE(0x41bede20);
    old.empty=BYTE(0x41bfa7c1);old.display=BYTE(0x41bfa7c6);
    encode(next_total,5,plan.total);encode(next_sensor,4,plan.sensor);
    dirty=1;
    if(!write_verified(0,totals[i],5,next_total) || !write_verified(0,sensors[i],4,next_sensor) ||
       !masked_cpu(0x6ab,hardware_bit,plan.near ? 0 : hardware_bit) ||
       !masked_cpu(0x624,pair,plan.near ? 1u<<(2*physical[i]) : 0)) goto rollback;
    if(((one_fn)(uintptr_t)0x403fae51)(3)!=0 || !critical_enter()) goto rollback;
    if((BYTE(0x41bfa7cd)&high) || (BYTE(0x41bfa8aa)&bit) ||
       WORD(0x42195be0)!=0 || QUAD(0x42354e00+8*i)!=old.ram_total ||
       WORD(0x42354e88+4*i)!=old.ram_sensor || BYTE(0x42195bff)!=1 ||
       QUAD(0x42354f58+8*i)!=old.pending || BYTE(0x42354e20+i)!=old.total_fraction ||
       BYTE(0x42354e98+i)!=old.sensor_fraction || BYTE(0x42354f78+i)!=old.pending_fraction ||
       (BYTE(0x41bfa7c5)&bit)!=(old.near&bit) || (BYTE(0x41bede4f)&high)!=(old.mirror&high)) {
        critical_leave();goto rollback;
    }
    ram_applied=1;
    QUAD(0x42354e00+8*i)=plan.total;
    WORD(0x42354e88+4*i)=plan.sensor;
    QUAD(0x42354f58+8*i)=0;
    BYTE(0x42354e20+i)=0;BYTE(0x42354e98+i)=0;BYTE(0x42354f78+i)=0;
    ((near_fn)(uintptr_t)0x402a48f3)(physical[i],plan.near ? 0 : 1);
    BYTE(0x41bede20)=(unsigned char)((BYTE(0x41bede20)&~hardware_bit)|(plan.near ? 0 : hardware_bit));
    BYTE(0x41bfa7c1)=(unsigned char)((BYTE(0x41bfa7c1)&~(bit|high))|(plan.near ? high : 0));
    BYTE(0x41bfa7c6)=(unsigned char)((BYTE(0x41bfa7c6)&~high)|(plan.near ? high : 0));
    critical_leave();
    /* Native getter reads the committed storage and real native state flags. */
    if(((color_fn)(uintptr_t)0x40457ad7)(colors[i])!=request->remaining[i] ||
       !cfw_read_state(i,&current) || current.total!=plan.total || current.sensor!=plan.sensor ||
       current.near!=plan.near || current.gated_empty ||
       !check_cpu(0x6ab,hardware_bit,plan.near ? 0 : hardware_bit) ||
       !check_cpu(0x624,pair,plan.near ? 1u<<(2*physical[i]) : 0)) goto rollback;
    result=CFW_SAVE_OK;
    goto finish;
rollback:
    rollback_ok=1;
    if(dirty) {
        if(!write_verified(0,totals[i],5,old.total)) rollback_ok=0;
        if(!write_verified(0,sensors[i],4,old.sensor)) rollback_ok=0;
        if(!masked_cpu(0x6ab,hardware_bit,old.latch)) rollback_ok=0;
        if(!masked_cpu(0x624,pair,old.warning)) rollback_ok=0;
        if(ram_applied) {
            if(critical_enter()) {restore_ram(i,&old);critical_leave();}
            else rollback_ok=0;
        }
    }
    result=rollback_ok ? CFW_SAVE_IO_ROLLED_BACK : CFW_SAVE_ROLLBACK_FAILED;
finish:
    if(reserved) ((void_one_fn)(uintptr_t)0x403fae29)(3);
    ((void_one_fn)(uintptr_t)0x4042153d)(mutex);
    if(result==CFW_SAVE_OK) ((notify_fn)(uintptr_t)0x40403399)();
    return result;
}

int cfw_count_based_sensor(unsigned index)
{
    static const unsigned channels[4]={2,3,5,4};
    static const unsigned order[4]={0,2,1,3};
    unsigned char raw[5],latch;
    unsigned i,kind;
    uint32_t t,l,sample;
    int full=0;
    if(index>=4) return 0;
    if(((handle_fn)(uintptr_t)0x403e180f)()!=-1) {
        sample=((color_fn)(uintptr_t)0x4040bcc3)(channels[index]);
        BYTE(0x41bedea4+index)=(unsigned char)sample;
        full=sample>=0x77;
    } else if(io(1,0x6ab,1,&latch,0)) full=(latch&(1u<<index))!=0;
    i=order[index];
    /* Freeze the logical latch while native printer starts are blocked. This
     * prevents seeing a newly written N before its S/flags/RAM publication. */
    if(BYTE(0x42195bff)) return (BYTE(0x41bfa7c5)&(1u<<i))==0;
    kind=BYTE(i<2 ? 0x41bfa89b : 0x41bfa89a);
    kind=(i==0 || i==2) ? kind&15 : kind>>4;
    if(!kind || kind>5 || !io(0,totals[i],5,raw,0)) return full;
    t=((color_fn)(uintptr_t)0x40283b4b)(colors[i]);
    l=((color_fn)(uintptr_t)0x40283ddf)(colors[i]);
    if(t<=l) return full;
    return decode(raw,5)<t-l;
}
