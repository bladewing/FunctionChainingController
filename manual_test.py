import itertools, time, json
from urllib.request import urlopen, Request
from werkzeug.datastructures import ImmutableMultiDict
grps = ["fw","ddos","ips"]
FCC_URL = "http://localhost:5000/manual"

perms = list(itertools.permutations(grps))
iterate_list = list()
STANDARD_CONF = ("ddos", "fw", "ips")
perms.remove(STANDARD_CONF)

print(perms[0])

for conf in perms:
    time.sleep(10)
    conn = Request(FCC_URL, json.dumps(conf).encode("utf-8"),
                   {'Content-Type': 'application/json'})
    resp = urlopen(conn)
    print(resp.getcode())