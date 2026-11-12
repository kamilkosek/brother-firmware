#!/usr/bin/env python3
"""Build/test custom-web components locally. Never accesses the printer.

The optional ARM executable is a link check, not a printer firmware image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def run(argv, **kwargs):
    return subprocess.run([str(x) for x in argv], check=True, text=True,
                          capture_output=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    cc = shutil.which('cc')
    if not cc:
        parser.error('A host C compiler (cc) is required')
    report = {'firmware_image': False, 'printer_access': False, 'tests': []}
    sources = []
    with tempfile.TemporaryDirectory(prefix='brother-web-check-') as temp:
        root = Path(temp)
        for name in ['web_request', 'native_level_model']:
            source = HERE.parent/'src'/(name+'.c')
            test = HERE.parent/'tests'/('test_'+name+'.c')
            sources += [source, test, HERE.parent/'src'/(name+'.h')]
            executable = root / name
            run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                 '-I', HERE.parent/'src', source, test, '-o', executable])
            result = run([executable])
            report['tests'].append({'module': name, 'passed': True,
                                    'output': result.stdout.strip()})
        if args.zig:
            output = root/'components-link-check.elf'
            env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(root/'zig-global'),
                       ZIG_LOCAL_CACHE_DIR=str(root/'zig-local'))
            run([args.zig, 'cc', '-target', 'thumbeb-freestanding-eabi',
                 '-mcpu=arm926ej_s', '-mthumb', '-ffreestanding', '-fno-builtin',
                 '-O2', '-nostdlib', '-Wl,--entry=cfw_validate_level_request',
                 '-Wl,-u,cfw_native_display', '-Wl,-u,cfw_native_counter_plan',
                 HERE.parent/'src'/ 'web_request.c', HERE.parent/'src'/ 'native_level_model.c', '-o', output], env=env)
            raw = output.read_bytes()
            if raw[:7] != b'\x7fELF\x01\x02\x01' or int.from_bytes(raw[18:20], 'big') != 40:
                raise ValueError('Link check did not produce an ARM ELF32 big-endian executable')
            if not int.from_bytes(raw[24:28], 'big') & 1:
                raise ValueError('Link check entry is not Thumb')
            if int.from_bytes(raw[36:40], 'big') & 0x00800000:
                raise ValueError('BE8 instructions do not match the original BE32 firmware')
            nm = shutil.which('nm')
            if not nm:
                raise RuntimeError('nm is required to check unresolved ARM symbols')
            if run([nm, '-u', output]).stdout.strip():
                raise ValueError('Unresolved symbols in ARM link check')
            symbols = run([nm, '-g', output]).stdout
            for name in ['cfw_validate_level_request', 'cfw_native_display', 'cfw_native_counter_plan']:
                if not any(line.split()[-1:] == [name] for line in symbols.splitlines()):
                    raise ValueError('Linker discarded required component: '+name)
            report['arm_link_check'] = {'passed': True, 'architecture': 'ARM32 big-endian',
                'instruction_mode': 'Thumb-1', 'instruction_endian': 'BE32',
                'unresolved_symbols': False, 'firmware_image': False,
                'sha256': hashlib.sha256(raw).hexdigest()}
    report['source_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    rendered = json.dumps(report, indent=2)+'\n'
    if args.report:
        args.report.write_text(rendered)
    print(rendered, end='')


if __name__ == '__main__':
    main()
