"""Lab acceptance: real HTTP workers, benign Brotli traffic and staged runtime replacement.

Downloads official affected/fixed Node 24 releases into temporary directories.
Binds only ephemeral IPv4 loopback ports; no exploit payloads or host installations.
"""
import base64
import http.client
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path

from test_node2shell_audit import audit
from verify_release import verified_binary


SERVICE = r'''
const http = require('node:http');
const zlib = require('node:zlib');
const message = 'node2shell benign service acceptance';
const server = http.createServer((req, res) => {
  if (req.method !== 'POST' || req.url !== '/decode' || req.headers['content-encoding'] !== 'br') {
    res.writeHead(400); res.end(); return;
  }
  const chunks = []; let length = 0;
  req.on('data', chunk => {
    length += chunk.length;
    if (length > 1024) req.destroy(); else chunks.push(chunk);
  });
  req.on('end', () => zlib.brotliDecompress(Buffer.concat(chunks), (error, data) => {
    if (error) { res.writeHead(400); res.end(); return; }
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({pid: process.pid, text: data.toString()}));
  }));
});
server.listen(0, '127.0.0.1', () => console.log(JSON.stringify({
  pid: process.pid, port: server.address().port,
  payload: zlib.brotliCompressSync(Buffer.from(message)).toString('base64')
})));
process.stdin.resume();
process.stdin.on('data', () => server.close(() => process.exit(0)));
process.stdin.on('end', () => server.close(() => process.exit(0)));
'''


def stop_service(service):
    process = service['process']
    if process.poll() is None:
        try:
            process.stdin.write('stop\n')
            process.stdin.flush()
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait(timeout=10)
    for stream in (process.stdin, process.stdout, process.stderr):
        stream.close()


def start_service(binary, script, stack):
    environment = {'PATH': os.defpath}
    if sys.platform == 'win32':
        environment['SystemRoot'] = str(audit.windows_system_directory().parent)
    process = subprocess.Popen([str(binary), str(script)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=environment)
    service = {'process': process, 'binary': str(binary)}
    stack.callback(stop_service, service)
    ready = queue.Queue()
    reader = threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True)
    reader.start()
    line = ready.get(timeout=20)
    assert line, 'HTTP worker did not start'
    service.update(json.loads(line))
    assert service['pid'] == process.pid and 0 < service['port'] < 65536
    service['payload'] = base64.b64decode(service['payload'], validate=True)
    return service


def request(service):
    connection = http.client.HTTPConnection('127.0.0.1', service['port'], timeout=5)
    try:
        connection.request('POST', '/decode', body=service['payload'],
                           headers={'Content-Encoding': 'br', 'Content-Type': 'application/octet-stream'})
        response = connection.getresponse()
        data = json.loads(response.read(2048))
        assert response.status == 200 and data == {
            'pid': service['pid'], 'text': 'node2shell benign service acceptance'}, data
    finally:
        connection.close()


def check_services(root, services, proof, statuses, phase, stale=(), missing=False):
    paths = sorted({s['binary'] for s in services})
    config = {'schema': 1, 'scope': 'Disposable loopback HTTP services', 'coverage_confirmed': True,
              'runtimes': [{'label': 'Reviewed lab HTTP decoder workers', 'kind': 'node', 'path': path,
                            'exposure': {audit.BROTLI_CVE: {
                                'reachability': 'reachable',
                                'source': 'verify_service.py fixture: every worker accepts br bodies at /decode'}}}
                           for path in paths]}
    if missing:
        config['runtimes'].append({'label': 'Missing expected worker', 'kind': 'node',
                                   'path': str(root / 'missing-node')})
    inv, evidence = root / 'inventory.json', root / 'evidence.json'
    inv.write_text(json.dumps(config), encoding='utf-8')
    evidence.write_text(json.dumps(proof), encoding='utf-8')
    stop = threading.Event()
    failures = []
    counts = {s['pid']: 0 for s in services}

    def traffic():
        try:
            deadline = time.monotonic() + 120
            while not stop.is_set() and time.monotonic() < deadline:
                for service in services:
                    request(service)
                    counts[service['pid']] += 1
                stop.wait(0.01)
        except Exception as exc:
            failures.append(exc)

    # Establish reachability before starting concurrent traffic and inspection.
    for service in services:
        request(service)
    worker = threading.Thread(target=traffic)
    worker.start()
    try:
        run = subprocess.run([sys.executable, str(Path(audit.__file__).resolve()),
                              '--inventory', str(inv), '--evidence', str(evidence), '--json'],
                             capture_output=True, text=True, timeout=120)
    finally:
        stop.set()
        worker.join(timeout=25)
    assert not worker.is_alive() and not failures, failures
    assert all(counts.values()), counts
    report = json.loads(run.stdout)['reports'][0]
    assert run.returncode == report['exit_status'], report
    own = [r for r in report['runtimes'] if r['pid'] in statuses and r['kind'] == 'node']
    assert {r['pid'] for r in own} == set(statuses), (own, report['issues'])
    for row in own:
        expected = statuses[row['pid']]
        cves = row['cve_results']
        if sys.platform == 'win32':
            assert row['status'] == 'UNKNOWN' and row['file_status'] == expected, row
            assert all(r['status'] == 'UNKNOWN' for r in cves.values()), row
            cves = row['file_cve_results']
        elif row['pid'] in stale and sys.platform == 'darwin':
            assert row['status'] == 'UNKNOWN' and row['restart_needed'], row
            assert all(r['status'] == 'UNKNOWN' for r in cves.values()), row
            continue
        else:
            assert row['status'] == expected, row
            if row['pid'] in stale:
                assert row['restart_needed'], row
        assert {cve: r['status'] for cve, r in cves.items()} == {
            cve: 'NOT_AFFECTED' if cve in ('CVE-2026-106070', 'CVE-2026-106071') else expected
            for cve in audit.CVES}, row
        exposed = expected == 'AFFECTED' and sys.platform != 'win32'
        assert (row['exploitability'] == 'POTENTIALLY_EXPLOITABLE') == exposed, row
    if missing:
        assert any(d['code'] == 'EXPECTED_RUNTIME_MISSING' for d in report['diagnostics']), report
        assert report['verdict'] != 'PATCHED', report
    elif not report['issues'] and len(own) == len(report['runtimes']):
        if sys.platform == 'win32' or (sys.platform == 'darwin' and stale):
            expected = 'UNKNOWN'
        else:
            expected = 'AFFECTED' if 'AFFECTED' in statuses.values() else 'PATCHED'
        assert report['verdict'] == expected, report
    print(f'{phase}: {len(own)} HTTP workers, {sum(counts.values())} valid requests during audit; '
          f'worker checks passed; namespace={report["verdict"]}', flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix='node2shell-service-') as directory, ExitStack() as stack:
        root = Path(directory).resolve()
        old_dir, fixed_dir = root / 'affected', root / 'fixed'
        old_dir.mkdir()
        fixed_dir.mkdir()
        old, old_proof, target = verified_binary('24.22.0', old_dir)
        fixed, fixed_proof, _ = verified_binary('24.22.1', fixed_dir)
        renamed = fixed.with_name('service-runtime' + fixed.suffix)
        fixed.rename(renamed)
        fixed = renamed
        proof = {'schema': 1, 'builds': old_proof['builds'] + fixed_proof['builds']}
        script = root / 'service.cjs'
        script.write_text(SERVICE, encoding='utf-8')
        affected = [start_service(old, script, stack) for _ in range(2)]
        patched = [start_service(fixed, script, stack) for _ in range(2)]
        statuses = {s['pid']: 'AFFECTED' for s in affected} | {s['pid']: 'PATCHED' for s in patched}
        check_services(root, affected + patched, proof, statuses, 'Mixed affected/fixed')
        stale = set()
        if sys.platform != 'win32':
            replacement = old.with_name('replacement')
            shutil.copy2(fixed, replacement)
            os.replace(replacement, old)
            stale = {s['pid'] for s in affected}
            assert audit.inspect_file({'kind': 'node', 'path': str(old)}, None, proof)['status'] == 'PATCHED'
            check_services(root, affected + patched, proof, statuses, 'Disk replaced; old workers retained', stale)
        for index, previous in enumerate(affected):
            stop_service(previous)
            statuses.pop(previous['pid'])
            stale.discard(previous['pid'])
            replacement = start_service(fixed if sys.platform == 'win32' else old, script, stack)
            statuses[replacement['pid']] = 'PATCHED'
            patched.append(replacement)
            check_services(root, affected[index + 1:] + patched, proof, statuses,
                           f'Rolling restart {index + 1}/2', stale)
        check_services(root, patched, proof, statuses, 'Missing expected worker', missing=True)
        print(f'PASS {target}: HTTP reachability, renamed runtime, mixed versions and restart checks', flush=True)


if __name__ == '__main__':
    main()
