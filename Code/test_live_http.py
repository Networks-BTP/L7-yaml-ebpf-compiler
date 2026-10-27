#!/usr/bin/env python3
"""
End-to-end test on a real interface (needs root, clang, libbpf-dev, gcc):

    sudo python3 tests/test_live_http.py <path/to/dslc> <http11.yaml>

Generates the program with --telemetry, builds it, starts a local HTTP server on 127.0.0.1:<port from spec>,
attaches the XDP program to the loopback interface, sends real HTTP requests (python http.client) and
checks the events printed by the loader and the counters it reports.
"""
import http.client, os, re, signal, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

dslc, spec = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
port = int(re.search(r"^port:\s*(\d+)", open(spec).read(), re.M).group(1))
work = tempfile.mkdtemp(prefix="dsl_live_")
subprocess.run([dslc, "--telemetry", spec, work], check=True, capture_output=True)
subprocess.run(["make", "-C", work], check=True, capture_output=True)

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)      # consume a request body, if any
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    do_POST = do_GET
    def log_message(self, *a): pass
srv = HTTPServer(("127.0.0.1", port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

loader = subprocess.Popen([os.path.join(work, "loader"), "-v", "-c", "-g", "-o", os.path.join(work, "tracer.bpf.o"), "lo"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=work)
first = loader.stderr.readline()          # "attached to ..." appears once the program is loaded (can take seconds)
if "attached" not in first:
    print("loader failed:", first, loader.stderr.read()); sys.exit(1)

sent = [("GET", "/index.html", {"X-Custom": "   padded value \t"}), ("GET", "/a/b?x=1&y=2", {}),
        ("POST", "/submit", {}), ("GET", "/" + "a" * 200, {})]   # the last URI exceeds the 128-byte cap
for m, p, h in sent:
    c = http.client.HTTPConnection("127.0.0.1", port)
    c.request(m, p, body=b"hello" if m == "POST" else None, headers=h); c.getresponse().read(); c.close()
time.sleep(1)
loader.send_signal(signal.SIGINT)
out, err = loader.communicate(timeout=10)
srv.shutdown()
print(out.strip()); print("loader stderr:", (first + err).strip())

ok = True
def check(cond, msg):
    global ok; ok &= bool(cond); print(f"  [{'ok ' if cond else 'FAIL'}] {msg}")
check('req.method="GET" req.uri="/index.html" req.version="HTTP/1.1"' in out, "GET /index.html parsed")
check('req.uri="/a/b?x=1&y=2"' in out, "URI with query string parsed")
check('req.method="POST" req.uri="/submit"' in out, "POST parsed")
check('h1.name="Host"' in out, "first header name is Host")
check("a" * 150 not in out, "over-long URI is not reported")
check(out.count("req.method=") == 3, "exactly 3 requests reported with -c (replies hidden)")
m = re.search(r"stats: matched=(\d+) parsed=(\d+) rejected=(\d+) filtered=(\d+)", out)
check(m and int(m.group(3)) >= 1, "counter 'rejected' saw the over-long URI")
check("verifier: processed" in out, "verifier statistics reported")
print("ALL PASSED" if ok else "SOME TESTS FAILED"); sys.exit(0 if ok else 1)