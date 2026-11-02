#!/usr/bin/env python3
"""Generate the real bindings; intercept installation before it touches policy."""
import argparse
import importlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import sysconfig
import tempfile

CASES = (
    'install_arity', 'install_extra', 'install_handle', 'info_arity',
    'info_extra', 'info_handle', 'info_modinfo', 'install_buffer',
    'info_buffer', 'install_name', 'install_ext', 'install_error',
    'info_error', 'install_success', 'info_success',
)


def exercise(case):
    module = importlib.import_module('_semanage')
    for _ in range(100):
        data = bytearray(b'reject' if case.endswith('_error') else b'a\0\xffz')
        calls = {
            'install_arity': lambda: module.semanage_module_install(),
            'install_extra': lambda: module.semanage_module_install(None, data, 'name', 'cil', 0),
            'install_handle': lambda: module.semanage_module_install(object(), data, 'name', 'cil'),
            'info_arity': lambda: module.semanage_module_install_info(),
            'info_extra': lambda: module.semanage_module_install_info(None, None, data, 0),
            'info_handle': lambda: module.semanage_module_install_info(object(), None, data),
            'info_modinfo': lambda: module.semanage_module_install_info(None, object(), data),
            'install_buffer': lambda: module.semanage_module_install(None, object(), 'name', 'cil'),
            'info_buffer': lambda: module.semanage_module_install_info(None, None, object()),
            'install_name': lambda: module.semanage_module_install(None, data, object(), 'cil'),
            'install_ext': lambda: module.semanage_module_install(None, data, 'name', object()),
            'install_error': lambda: module.semanage_module_install(None, data, 'name', 'cil'),
            'info_error': lambda: module.semanage_module_install_info(None, None, data),
            'install_success': lambda: module.semanage_module_install(None, data, 'name', 'cil'),
            'info_success': lambda: module.semanage_module_install_info(None, None, data),
        }
        try:
            result = calls[case]()
        except (TypeError, OSError) as error:
            if case.endswith('_error'):
                assert isinstance(error, OSError) and error.errno == 13
            else:
                assert not case.endswith('_success') and isinstance(error, TypeError)
        else:
            assert case.endswith('_success') and result == 0
        # A leaked buffer export would prevent resizing after the call.
        data.extend(b'x')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', type=Path)
    parser.add_argument('--case', choices=CASES)
    args = parser.parse_args()
    if args.case:
        exercise(args.case)
        return

    component = Path(__file__).resolve().parents[2]
    library = (args.library or component / 'src/libsemanage.so.2').resolve()
    assert library.is_file(), library
    with tempfile.TemporaryDirectory(prefix='semanage-buffer-') as tmp:
        temp = Path(tmp)
        wrapper = temp / 'wrapper.c'
        subprocess.run(shlex.split(os.environ.get('SWIG', 'swig')) + [
            '-python', '-I' + str(component / 'include'),
            '-I' + str(component / 'src'), '-outdir', tmp, '-o', str(wrapper),
            str(component / 'src/semanageswig_python.i')], check=True)
        source = wrapper.read_text()
        # Inspect both entry points: stack contents can hide an invalid release.
        for api, view in (('semanage_module_install', 'view2'),
                          ('semanage_module_install_info', 'view3')):
            start = source.index('_wrap_' + api + '(')
            body = source[start:source.index('\n}\n', start)]
            declaration = re.search(r'Py_buffer\s+' + view + r'\s*=\s*\{\s*0\s*\}', body)
            assert declaration, api + ': buffer must be initialized at declaration'
            assert declaration.start() < body.index('SWIG_Python_UnpackTuple')
        output = temp / ('_semanage' + sysconfig.get_config_var('EXT_SUFFIX'))
        subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
            '-shared', '-fPIC', '-O2', '-g', '-I' + sysconfig.get_path('include'),
            '-I' + str(component / 'include'), str(wrapper),
            str(Path(__file__).with_name('module_buffer_stubs.c')), str(library),
            '-Wl,--wrap=semanage_module_install,--wrap=semanage_module_install_info',
            '-Wl,-rpath,' + str(library.parent), '-o', str(output)], check=True)
        env = dict(os.environ, PYTHONPATH=tmp)
        for case in CASES:
            subprocess.run([sys.executable, str(Path(__file__).resolve()), '--case', case],
                           env=env, check=True, timeout=30)
        print('module-buffer: 15 scenarios, 1500 calls passed')


if __name__ == '__main__':
    main()
