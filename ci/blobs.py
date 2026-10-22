"""List containers/blobs for a storage account using a shared key, and dump small blobs."""
import base64
import datetime
import hashlib
import hmac
import os
import re
import urllib.request

ACCT = os.environ["ACCT"]
KEY = os.environ["AKEY"]


def get(path, params):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    canon = f"/{ACCT}{path}\n" + "\n".join(f"{k}:{v}" for k, v in sorted(params.items()))
    blob = f"GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:{now}\nx-ms-version:2021-08-06\n{canon}"
    sig = base64.b64encode(
        hmac.new(base64.b64decode(KEY), blob.encode("utf-8"), hashlib.sha256).digest()
    ).decode()
    query = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    url = f"https://{ACCT}.blob.core.windows.net{path}" + (f"?{query}" if query else "")
    req = urllib.request.Request(
        url,
        headers={
            "x-ms-date": now,
            "x-ms-version": "2021-08-06",
            "Authorization": f"SharedKey {ACCT}:{sig}",
        },
    )
    return urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")


try:
    listing = get("/", {"comp": "list"})
    containers = re.findall(r"<Name>([^<]+)</Name>", listing)
    print(f"containers: {containers}")
    for container in containers:
        body = get(f"/{container}", {"comp": "list", "restype": "container"})
        names = re.findall(r"<Name>([^<]+)</Name>", body)
        print(f"== container {container}: {names}")
        for name in names:
            print(f"-- blob {container}/{name}")
            try:
                print(get(f"/{container}/{name}", {})[:6000])
            except Exception as exc:  # noqa: BLE001
                print("blob error", exc)
except Exception as exc:  # noqa: BLE001
    print("storage error", exc)
