# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Fixed isolated parser executable. No SDK root, broker credential or file inputs."""
import base64,json,os,sys
from pathlib import Path
# -I -S disables user site, environment injection and .pth startup. Paths below
# are fixed by the host, never taken from the content request.
sys.path.insert(0,str(Path(__file__).resolve().parent))
if len(sys.argv)==2:sys.path.append(sys.argv[1])
from quarantine_parser import extract_safe_text

def main():
    if os.name!='nt':
        import resource,threading,time
        resource.setrlimit(resource.RLIMIT_CPU,(8,resource.getrlimit(resource.RLIMIT_CPU)[1]))
        resource.setrlimit(resource.RLIMIT_FSIZE,(0,resource.getrlimit(resource.RLIMIT_FSIZE)[1]))
        if sys.platform!='darwin':resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,resource.getrlimit(resource.RLIMIT_AS)[1]))
        else:
            def watch():
                while True:
                    if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss>512*1024**2:os._exit(77)
                    time.sleep(.02)
            threading.Thread(target=watch,daemon=True).start()
    try:
        data=sys.stdin.buffer.read(800000)
        if len(data)>=800000:raise ValueError()
        request=json.loads(data)
        if set(request)!={'content','filename'}:raise ValueError()
        result=extract_safe_text(base64.b64decode(request['content'],validate=True),request['filename'])
        print(json.dumps(result,ensure_ascii=True))
    except Exception:
        print('{"error":"content_quarantined"}');raise SystemExit(1)
if __name__=='__main__':main()
