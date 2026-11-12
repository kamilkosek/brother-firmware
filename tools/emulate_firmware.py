#!/usr/bin/env python3
"""Execute compiled custom 0.3 against mocked device IO and resource guards.

No network or printer access. Storage, native firmware calls, resource locking
and sensor ADC are mocks; this does not establish hardware persistence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
from build_firmware import payload_from_elf,FLASH

HERE=Path(__file__).resolve().parent
STACK=0x10000000;REQUEST=0x20000000;STOP=0x30000000
TOTALS=[0x60,0x6a,0x65,0x6f];SENSORS=[0x3c,0x44,0x40,0x48]
NATIVE_COLORS=[0,0x11,0x12,0x13]
CALLS={0x40643032,0x4072a65c,0x4072acb4,0x40751e74,0x406ef196,0x4065ace8,
       0x40283b4a,0x40283dde,0x40282c48,0x404b1b3a,0x403cc8a6,0x403c9ce4,0x403c9d16,
       0x404214a4,0x4042153c,0x403fadee,0x403fae28,0x403fae50,0x402a48f2,0x40457ad6,
       0x40403398,0x403e180e,0x4040bcc2,0x400578e8,0x4044b764}


def form(mask=8,percent=100,expected=9000):
    levels=[80,75,90,3]
    if mask in [1,2,4,8]:levels[[1,2,4,8].index(mask)]=percent
    fields=['cfw_action=set_levels','cfw_confirm=1']
    fields += [f'cfw_{c}={v}' for c,v in zip(['bk','y','c','m'],levels)]
    fields += [f'cfw_mask={mask}',f'cfw_expect_{["bk","y","c","m"][[1,2,4,8].index(mask)] if mask in [1,2,4,8] else "m"}={expected}']
    return '&'.join(fields).encode()


class Device:
    def __init__(self,elf,*,method='POST',authenticated=1,origin='http://192.0.2.1',
                 body=None,busy=False,mutex_busy=False,fail_write=0,fail_readback=0,
                 fail_all_writes=False,bad_native_percent=False,history=1,persisted=None,
                 pending_race=False,fail_critical=False):
        self.blob,self.entry=payload_from_elf(elf)
        self.uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_BIG_ENDIAN)
        u=self.uc;u.mem_map(FLASH,0x10000);u.mem_write(FLASH,self.blob)
        for page in {a&~4095 for a in CALLS}|{0x402a4000}:u.mem_map(page,4096)
        for base,size in [(STACK,0x10000),(REQUEST,0x10000),(STOP,4096),
                          (0x41be0000,0x20000),(0x42190000,0x20000),(0x42350000,0x10000)]:
            u.mem_map(base,size)
        self.output=[];self.calls=[];self.writes=[];self.notifications=0
        self.critical=False
        self.pending_race=pending_race;self.fail_critical=fail_critical
        self.method=method;self.authenticated=authenticated
        self.busy=busy;self.mutex_busy=mutex_busy;self.locked=False;self.reserved=0
        self.fail_write=fail_write;self.fail_readback=fail_readback
        self.fail_all_writes=fail_all_writes;self.write_attempts=0;self.corrupt_next=None
        self.bad_native_percent=bad_native_percent;self.history=history;self.returned=False
        self.head={}
        for a,v in zip(TOTALS,[2000,2500,1000,9000]):self.head[a]=v.to_bytes(5,'big')
        for a,v in zip(SENSORS,[0,0,0,1700]):self.head[a]=v.to_bytes(4,'big')
        self.cpu={0x6ab:b'\x07',0x624:b'\x40'}
        if persisted:self.head,self.cpu=map(dict,persisted)
        for i in range(4):
            self.put64(0x42354e00+8*i,int.from_bytes(self.head[TOTALS[i]],'big'))
            self.put32(0x42354e88+4*i,int.from_bytes(self.head[SENSORS[i]],'big'))
            self.put64(0x42354f58+8*i,123+i)
            for a in [0x42354e20,0x42354e98,0x42354f78]:self.put8(a+i,7+i)
        self.put8(0x41bfa7c5,8);self.put8(0x41bede4f,0x80)
        self.put8(0x41bfa7c1,0x80);self.put8(0x41bfa7c6,0x80)
        self.put8(0x41bede20,self.cpu[0x6ab][0])
        self.put8(0x41bfa89a,0x11);self.put8(0x41bfa89b,0x11)
        self.put32(0x41bf18e0,55)
        self.put32(REQUEST,0x013106c1);self.put32(REQUEST+32,REQUEST+0x1000)
        self.put32(REQUEST+0x1000+44,REQUEST+0x2000)
        self.put32(REQUEST+0x2000+72,REQUEST+0x3000)
        self.put32(REQUEST+0x2000+76,REQUEST+0x4000)
        body=form() if body is None else body
        u.mem_write(REQUEST+0x4000,body+b'\0')
        headers={'Host':'192.0.2.1','Origin':origin,'Content-Length':str(len(body)),
                 'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'}
        self.headers={}
        for i,(k,v) in enumerate(headers.items()):
            if v is not None:
                a=REQUEST+0x5000+i*256;self.string(a,v);self.headers[k]=a
        self.before_head=dict(self.head);self.before_cpu=dict(self.cpu)
        self.before_ram=self.ram_snapshot()
        self.selected=8
        self.allowed=[]
        u.hook_add(UC_HOOK_CODE,self.code)
        u.hook_add(UC_HOOK_MEM_WRITE,self.write_watch)

    def put8(self,a,v):self.uc.mem_write(a,bytes([v&255]))
    def put32(self,a,v):self.uc.mem_write(a,struct.pack('>I',v))
    def put64(self,a,v):self.uc.mem_write(a,struct.pack('>Q',v))
    def get8(self,a):return self.uc.mem_read(a,1)[0]
    def get32(self,a):return int.from_bytes(self.uc.mem_read(a,4),'big')
    def string(self,a,s):self.uc.mem_write(a,s.encode()+b'\0')
    def text(self,a):
        out=bytearray()
        for i in range(8192):
            c=self.uc.mem_read(a+i,1)[0]
            if not c:return out.decode('ascii')
            out.append(c)
        raise AssertionError('Unterminated output string')

    def ram_snapshot(self):
        return {a:bytes(self.uc.mem_read(a,n)) for a,n in
                [(0x42354e00,36),(0x42354e88,20),(0x42354f58,36),
                 (0x41bfa7c1,6),(0x41bede4f,1),(0x41bede20,1)]}

    def percent(self,i):
        bit=1<<i
        if self.get8(0x41bfa7c1)&bit or self.get8(0x41bfa7cd)&(bit<<4) or self.get8(0x41bfa8aa)&bit:return 0
        if self.get8(0x41bfa7c5)&bit:
            s=int.from_bytes(self.head[SENSORS[i]],'big');v=1 if s>2000 else ((2000-s)//100)&255
        else:
            n=int.from_bytes(self.head[TOTALS[i]],'big');v=100 if n==0 else (1 if n>=10000 else ((10000-n)//100)&255)
        return min(100,v or 1)

    def code(self,u,a,size,data):
        if a==STOP:self.returned=True;u.emu_stop();return
        if FLASH<=a<FLASH+len(self.blob):return
        if a in [0x402a47e2,0x402a47e4,0x402a47e6]:return # execute the actual emitted veneer
        assert a in CALLS,f'Unexpected native call {a:#x}'
        self.calls.append(a)
        r=[u.reg_read(x) for x in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
        result=0
        if a==0x40643032:self.output.append(self.text(r[1]))
        elif a==0x406ef196:
            self.rendered=[self.percent(i) for i in range(4)]
            self.output.append('<div>original renderer mock</div>')
        elif a==0x4072acb4:self.put32(r[1],self.authenticated)
        elif a==0x4072a65c:
            assert self.text(r[1])=='REQUEST_METHOD';self.string(r[2],self.method)
        elif a==0x40751e74:result=self.headers.get(self.text(r[1]),0)
        elif a==0x404b1b3a:result=11
        elif a==0x403cc8a6:result=12
        elif a in [0x403c9ce4,0x403c9d16]:
            spec=self.get32(r[1]);pointer=self.get32(r[1]+4)
            if r[0]==11:store=self.head;address=spec>>24;n=(spec>>16)&255;bank='head'
            else:
                assert r[0]==12;store=self.cpu;address=spec>>16;n=spec&65535;bank='cpu'
            assert address in store and n==len(store[address])
            if a==0x403c9ce4:
                b=store[address]
                if self.corrupt_next==(bank,address):
                    b=bytes([b[0]^1])+b[1:];self.corrupt_next=None
                u.mem_write(pointer,b)
            else:
                assert self.locked and self.reserved==1 and not self.busy and not self.critical
                self.write_attempts+=1
                store[address]=bytes(u.mem_read(pointer,n))
                self.writes.append((bank,address,store[address].hex()))
                if self.pending_race and self.write_attempts==4:
                    old=int.from_bytes(u.mem_read(0x42354f70,8),'big')
                    self.put64(0x42354f70,old+1)
                if self.fail_readback==self.write_attempts:self.corrupt_next=(bank,address)
                if self.fail_all_writes or self.fail_write==self.write_attempts:result=0xffffffff
        elif a==0x40283b4a:result=10000
        elif a==0x40283dde:result=2000
        elif a==0x40282c48:result=self.history
        elif a==0x404214a4:
            assert r[0]==55 and r[1]==0 and r[2]==10
            if self.mutex_busy:result=0xffffffff
            else:assert not self.locked;self.locked=True
        elif a==0x4042153c:assert self.locked and self.reserved==0;self.locked=False
        elif a==0x403fadee:
            assert self.locked and r[0]==3
            if self.busy:result=1
            else:self.reserved+=1;self.put8(0x42195bff,self.reserved)
        elif a==0x403fae28:
            assert self.locked and r[0]==3 and self.reserved==1
            self.reserved-=1;self.put8(0x42195bff,self.reserved)
        elif a==0x403fae50:result=1 if self.busy else 0
        elif a==0x402a48f2:
            assert self.critical
            i=[0,2,1,3][r[0]];bit=1<<i;v=0 if r[1]==1 else bit
            self.put8(0x41bfa7c5,(self.get8(0x41bfa7c5)&~bit)|v)
            self.put8(0x41bede4f,(self.get8(0x41bede4f)&~(bit<<4))|(v<<4))
        elif a==0x40457ad6:
            result=self.percent(NATIVE_COLORS.index(r[0]))
            if self.bad_native_percent:result=0;self.bad_native_percent=False
        elif a==0x4065ace8:
            assert r[0]==0 and r[1] in range(0xac,0xb0)
            self.string(r[2],str(self.percent(r[1]-0xac)))
        elif a==0x40403398:
            assert not self.locked and not self.reserved;self.notifications+=1
        elif a==0x400578e8:
            assert not self.critical and self.get8(0x41bf3605)==0
            if self.fail_critical:result=0xffffffe7
            else:self.critical=True;self.put8(0x41bf3605,1)
        elif a==0x4044b764:
            assert self.critical
            self.critical=False;self.put8(0x41bf3605,0)
        elif a==0x403e180e:result=0
        elif a==0x4040bcc2:result=0 if r[0]==4 else 255
        u.reg_write(UC_ARM_REG_R0,result)
        u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))

    def write_watch(self,u,access,a,n,value,data):
        if STACK<=a and a+n<=STACK+0x10000:return
        allowed=[(0x41bedea4,4)]
        for i in range(4):
            if self.selected&(1<<i):
                allowed += [(0x42354e00+8*i,8),(0x42354e88+4*i,4),(0x42354f58+8*i,8),
                            (0x42354e20+i,1),(0x42354e98+i,1),(0x42354f78+i,1)]
        allowed += [(0x41bede20,1),(0x41bfa7c1,1),(0x41bfa7c6,1),
                    (0x41bfa7c5,1),(0x41bede4f,1)]
        assert any(start<=a and a+n<=start+size for start,size in allowed),f'Unexpected RAM write {a:#x}+{n}'
        if not 0x41bedea4<=a<0x41bedea8:assert self.locked and self.reserved==1 and self.critical

    def run(self,entry=None,arg=None):
        u=self.uc;self.returned=False
        u.reg_write(UC_ARM_REG_SP,STACK+0xffe0);self.put32(STACK+0xffe0,1)
        u.reg_write(UC_ARM_REG_LR,STOP|1)
        for register,v in [(UC_ARM_REG_R0,REQUEST if arg is None else arg),
                           (UC_ARM_REG_R1,0),(UC_ARM_REG_R2,0),(UC_ARM_REG_R3,0)]:u.reg_write(register,v)
        u.emu_start(self.entry if entry is None else entry,STOP+2,count=3000000)
        assert self.returned and not self.locked and self.reserved==0 and not self.critical
        return ''.join(self.output)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory',type=Path,default=HERE.parent/'build/control')
    p.add_argument('--report',type=Path)
    args=p.parse_args();elf=(args.directory/'control-payload.elf').read_bytes()
    manifest=json.loads((args.directory/'manifest.json').read_text())
    sensor=manifest['code_patch']['additional_changes']['sensor_hook']
    veneer=bytes.fromhex(sensor['after']);results=[]
    def record(name,d,ok=False):
        if not ok:assert d.head==d.before_head and d.cpu==d.before_cpu and d.ram_snapshot()==d.before_ram,name
        results.append({'case':name,'passed':True,'write_attempts':d.write_attempts,
                        'guard_released':not d.locked and not d.reserved})
    d=Device(elf);text=d.run()
    assert 'Saved and read back' in text
    assert int.from_bytes(d.head[0x6f],'big')==0 and int.from_bytes(d.head[0x48],'big')==0
    assert d.rendered==[80,75,90,100] and d.notifications==1
    for a in TOTALS[:-1]+SENSORS[:-1]:assert d.head[a]==d.before_head[a]
    assert d.cpu[0x6ab]==b'\x0f' and d.cpu[0x624]==b'\x00'
    assert d.get8(0x41bfa7c5)&8==0
    record('magenta_near_to_100',d,True)
    persisted=(dict(d.head),dict(d.cpu))
    d2=Device(elf,persisted=persisted);d2.uc.mem_write(0x402a47e2,veneer)
    d2.run(entry=0x402a47e3,arg=3)
    assert d2.uc.reg_read(UC_ARM_REG_R0)==1 and d2.get8(0x41bedea7)==0
    record('reboot_persisted_count_overrides_false_low_adc',d2)
    d3=Device(elf,persisted=persisted);assert 'since this page was loaded' in d3.run();record('stale_post_replay',d3)
    for mask,n in zip([1,2,4,8],[2000,2500,1000,9000]):
        d=Device(elf,body=form(mask,5,n));d.selected=mask;text=d.run();i=[1,2,4,8].index(mask)
        assert 'Saved and read back' in text
        assert int.from_bytes(d.head[TOTALS[i]],'big')==9500 and int.from_bytes(d.head[SENSORS[i]],'big')==1500
        for j in range(4):
            if j!=i:assert d.head[TOTALS[j]]==d.before_head[TOTALS[j]] and d.head[SENSORS[j]]==d.before_head[SENSORS[j]]
        d.uc.mem_write(0x402a47e2,veneer);d.run(entry=0x402a47e3,arg=[0,2,1,3][i])
        assert d.uc.reg_read(UC_ARM_REG_R0)==0
        record(f'color_{i}_to_5_percent',d,True)
    for name,kwargs,expected in [
        ('printer_busy',{'busy':True},'access is busy'),
        ('object_mutex_busy',{'mutex_busy':True},'access is busy'),
        ('not_logged_in',{'authenticated':0},'Sign in above'),
        ('foreign_origin',{'origin':'http://evil.example'},'Request rejected'),
        ('missing_origin',{'origin':None},'Request rejected'),
        ('zero_target',{'body':form(percent=0)},'Select exactly one color'),
        ('multiple_colors',{'body':form(mask=3)},'Select exactly one color'),
        ('stale_counter',{'body':form(expected=8999)},'since this page was loaded'),
        ('duplicate_field',{'body':form()+b'&cfw_m=50'},'Request rejected'),
        ('native_control_field',{'body':form()+b'&B518=1'},'Request rejected'),
        ('missing_confirmation',{'body':form().replace(b'cfw_confirm=1',b'cfw_confirm=0')},'Request rejected')]:
        d=Device(elf,**kwargs);text=d.run();assert expected in text,(name,text);assert not d.writes;record(name,d)
    for kind in ['write','readback']:
        for step in range(1,5):
            d=Device(elf,**{f'fail_{kind}':step});text=d.run()
            assert 'previous values were restored' in text,(kind,step,text)
            record(f'{kind}_failure_{step}_rolled_back',d)
    d=Device(elf,bad_native_percent=True);text=d.run();assert 'previous values were restored' in text
    record('native_percentage_mismatch_rolls_back_ram_and_storage',d)
    d=Device(elf,fail_all_writes=True);text=d.run();assert 'Restoration could not be fully verified' in text
    record('rollback_failure_explicitly_reported',d)
    for addr in [0x41bfa7c1,0x41bfa7cd,0x41bfa8aa]:
        d=Device(elf);d.put8(addr,0x80 if addr==0x41bfa7cd else 8);d.before_ram=d.ram_snapshot()
        text=d.run();assert 'blocking condition is active' in text;assert not d.writes;record(f'gate_{addr:x}_not_cleared',d)
    d=Device(elf,fail_critical=True);text=d.run()
    assert 'previous values were restored' in text
    assert 0x4044b764 not in d.calls
    record('failed_dispatch_disable_does_not_enable_foreign_section',d)
    d=Device(elf,pending_race=True);text=d.run()
    assert 'previous values were restored' in text
    assert d.head==d.before_head and d.cpu==d.before_cpu
    assert int.from_bytes(d.uc.mem_read(0x42354f70,8),'big')==127
    results.append({'case':'pending_usage_race_preserved_not_zeroed','passed':True,
                    'write_attempts':d.write_attempts,'guard_released':not d.locked and not d.reserved})
    for addr in [0x41bf3605,0x41bf3606,0x42195bff]:
        d=Device(elf);d.put8(addr,1);text=d.run()
        assert 'access is busy' in text and not d.writes
        assert d.get8(addr)==1
        record(f'preexisting_guard_{addr:x}_preserved',d)
    for near in [0,8]:
        d=Device(elf,persisted=persisted)
        d.put8(0x41bfa7c5,near);d.put8(0x42195bff,1);d.before_ram=d.ram_snapshot()
        d.uc.mem_write(0x402a47e2,veneer);d.run(entry=0x402a47e3,arg=3)
        assert d.uc.reg_read(UC_ARM_REG_R0)==int(not near) and d.get8(0x41bedea7)==0
        record(f'sensor_latch_frozen_during_reservation_{near}',d)
    report={'kind':'compiled-control-payload-emulation-with-mocked-native-devices',
        'hardware_test':False,'printer_access':False,'elf_sha256':hashlib.sha256(elf).hexdigest(),
        'candidate_sha256':manifest['output_sha256'],'cases':results}
    rendered=json.dumps(report,indent=2)+'\n'
    if args.report:args.report.write_text(rendered)
    print(rendered,end='')


if __name__=='__main__':main()
