#!/usr/bin/env python3
"""ELF 卡密门控定位器 (aarch64): 字符串 -> ADRP/ADD 引用 -> 判定分支"""
import sys, re, argparse
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf_kami_xref import Elf64

KEYS_DEFAULT = ['卡密','登录','成功','失败','过期','验证','错误','sdcard','配置',
                'card','kami','token','expire','login','success','password','授权']

def find_ascii_strings(data, base_va, keys, minlen=4):
    hits=[]
    for m in re.finditer(rb'[\x20-\x7e]{%d,}'%minlen, data):
        s=m.group().decode('utf8','replace'); low=s.lower()
        for k in keys:
            if k in s or k.lower() in low:
                hits.append((base_va+m.start(), s[:160])); break
    return hits

def find_cjk_strings(data, base_va, keys, minlen=2):
    hits=[]
    for k in keys:
        kb=k.encode('utf8'); start=0
        while True:
            i=data.find(kb,start)
            if i<0: break
            a,b=i,i+len(kb)
            while a>0 and (data[a-1]>=0x20 or data[a-1]>=0x80) and i-a<200: a-=1
            while b<len(data) and (data[b]>=0x20 or data[b]>=0x80) and b-i<200: b+=1
            s=data[a:b].decode('utf8','replace')
            s=''.join(c for c in s if c.isprintable() or ord(c)>0x2000).strip()
            hits.append((base_va+a,s[:160])); start=i+len(kb)
    return hits

def find_refs(insns, target_va):
    refs=[]; adrp_at={}
    for idx,ins in enumerate(insns):
        if ins.mnemonic!='adrp': continue
        p=ins.op_str.split(',')
        if len(p)!=2: continue
        try: page=int(p[1].strip().lstrip('#'),0)
        except ValueError: continue
        adrp_at[idx]=(p[0].strip(),page)
    tp=target_va & ~0xfff; to=target_va & 0xfff
    for idx,(reg,page) in adrp_at.items():
        if page!=tp: continue
        for j in range(idx+1,min(idx+8,len(insns))):
            ins=insns[j]
            if ins.mnemonic=='add':
                pp=ins.op_str.split(',')
                if len(pp)==3 and pp[0].strip()==reg and pp[1].strip()==reg:
                    try: off=int(pp[2].strip().lstrip('#'),0)
                    except ValueError: break
                    if off==to: refs.append((insns[idx].address,ins.address))
                    break
    return refs

def find_gate(insns, ref_idx, lookback=40):
    for k in range(ref_idx, max(0,ref_idx-lookback), -1):
        ins=insns[k]
        if ins.mnemonic in ('cbz','cbnz','tbz','tbnz'): return ins
        if ins.mnemonic in ('cmp','cmn','tst'):
            for m in range(k+1,min(k+3,len(insns))):
                if insns[m].mnemonic.startswith('b.') and insns[m].mnemonic!='b':
                    return insns[m]
    return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('elf'); ap.add_argument('--keys',default=','.join(KEYS_DEFAULT))
    ap.add_argument('--refs',type=int,default=20)
    a=ap.parse_args(); keys=a.keys.split(',')
    e=Elf64(a.elf); ro=e.by_name.get('.rodata'); tx=e.by_name.get('.text')
    if not ro or not tx: print('[!] missing sections'); return
    print('[*] %s rodata@0x%x+0x%x text@0x%x+0x%x'%(a.elf,ro['addr'],ro['size'],tx['addr'],tx['size']))
    rd=e.d[ro['off']:ro['off']+ro['size']]
    hits=find_ascii_strings(rd,ro['addr'],keys)+find_cjk_strings(rd,ro['addr'],keys)
    uniq={}
    for va,s in hits:
        if va not in uniq or len(s)>len(uniq[va]): uniq[va]=s
    hits=sorted(uniq.items()); print('[+] %d string hit(s)'%len(hits))
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    code=e.d[tx['off']:tx['off']+tx['size']]
    insns=list(md.disasm(code,tx['addr'])); print('[+] disasm %d insns'%len(insns))
    index={ins.address:i for i,ins in enumerate(insns)}
    shown=0
    for va,s in hits:
        if shown>=a.refs: break
        refs=find_refs(insns,va)
        if not refs: continue
        shown+=1
        print('\n'+'='*72); print('STR @0x%x  %r'%(va,s))
        for adrp_a,add_a in refs[:4]:
            ridx=index.get(add_a); gate=find_gate(insns,ridx) if ridx else None
            print('  ref: adrp 0x%x -> add 0x%x'%(adrp_a,add_a))
            if gate:
                print('  GATE?: 0x%x  %s %s'%(gate.address,gate.mnemonic,gate.op_str))
                i2=index[gate.address]
                for ins in insns[max(0,i2-3):i2+8]:
                    mk='>>' if ins.address==gate.address else '  '
                    print('   %s 0x%x  %-8s %s'%(mk,ins.address,ins.mnemonic,ins.op_str))

main()
