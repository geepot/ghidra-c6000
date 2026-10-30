#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise a packaged C6000 extension in a real, isolated, headed CodeBrowser tool.

Requires a desktop session (or xvfb-run on Linux). Never opens the user's projects.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
from zipfile import ZipFile

from check_archive import check_archive
from verify import ROOT, properties, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path, help='extension ZIP produced by tools/build.sh or verify.py')
    parser.add_argument('--ghidra', type=Path, default=os.environ.get('GHIDRA_INSTALL_DIR', '/opt/homebrew/opt/ghidra/libexec'))
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--keep-install', action='store_true', help='retain the isolated installation for debugging')
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    ghidra = args.ghidra.resolve()
    props = properties(ghidra / 'Ghidra/application.properties')
    major = props['application.java.min']
    candidates = [os.environ.get('JAVA_HOME', ''), f'/Library/Java/JavaVirtualMachines/temurin-{major}.jdk/Contents/Home',
                  f'/opt/homebrew/opt/openjdk@{major}/libexec/openjdk.jdk/Contents/Home', f'/usr/lib/jvm/temurin-{major}-jdk-amd64']
    java = next((Path(p) for p in candidates if p and (Path(p) / 'bin/javac').is_file()), None)
    if java is None:
        parser.error(f'set JAVA_HOME to a JDK {major} installation')
    work = Path(tempfile.mkdtemp(prefix='verify-gui-', dir=ROOT / 'scratch'))
    print(f'GUI verification artifacts: {work}', flush=True)
    archive = work / args.archive.name
    shutil.copy2(args.archive, archive)
    check_archive(archive, props['application.version'])
    install = work / 'ghidra'
    extensions = ghidra / 'Ghidra/Extensions'
    shutil.copytree(ghidra, install, symlinks=True,
                    ignore=lambda directory, names: names if Path(directory) == extensions else [])
    with ZipFile(archive) as source:
        source.extractall(install / 'Ghidra/Extensions')
    home = work / 'home';home.mkdir()
    env = os.environ.copy();env['JAVA_HOME'] = str(java)
    env['_JAVA_OPTIONS'] = f'-Duser.home={home} -Dapple.laf.useScreenMenuBar=false'
    report = {'archive': str(archive), 'source_archive': str(args.archive.resolve()),
              'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
              'ghidra': props['application.version'], 'passed': False}
    try:
        for endian in ('le', 'be'):
            run([sys.executable, ROOT / 'tests/fixtures/pipeline-c67x.py', work / f'{endian}.bin', work / f'{endian}.json',
                 *(['be'] if endian == 'be' else [])], work / f'generate-{endian}.log', env, args.timeout)
        classes = work / 'classes';classes.mkdir()
        classpath = os.pathsep.join(map(str, sorted((install / 'Ghidra').rglob('*.jar'))))
        run([java / 'bin/javac', '-cp', classpath, '-d', classes, ROOT / 'tests/gui/C6000GuiIntegration.java'],
            work / 'compile.log', env, args.timeout)
        run([java / 'bin/jar', '--create', '--file', install / 'Ghidra/Extensions/C6000/lib/C6000GuiTests.jar', '-C', classes, '.'],
            work / 'test-jar.log', env, args.timeout)
        command = [install / 'support/launch.sh', 'fg', 'jdk', 'C6000-Native-Test', '2G',
                   '-Djava.awt.headless=false', 'c6000.C6000GuiIntegration', work]
        report['command'] = list(map(str, command))
        output = run(command, work / 'gui.log', env, args.timeout)
        errors = re.findall(r'(?m)^(?:ERROR |Exception in thread)[^\n]*', output)
        if errors:
            report['framework_errors'] = errors
            raise RuntimeError('Native framework logged unexpected errors; see gui.log')
        result = work / 'result.txt'
        if not result.exists() or not re.fullmatch(r'C6000_GUI_INTEGRATION_OK checks=[1-9][0-9]*\n', result.read_text()):
            raise RuntimeError('Headed test did not produce its completion marker')
        report.update(passed=True, result=result.read_text().strip())
    except (RuntimeError, OSError, ValueError) as error:
        report['error'] = str(error)
    if not args.keep_install:
        shutil.rmtree(install)
    (work / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{'VERIFIED' if report['passed'] else 'FAILED'} GUI: {work / 'summary.json'}", flush=True)
    if not report['passed']:
        print(report['error'], file=sys.stderr)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
