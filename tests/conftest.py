import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pawpilot import squid  # noqa: E402
from pawpilot.settings import Settings  # noqa: E402

LOG = """\
1762770000.100 12 10.0.0.5 TCP_DENIED/403 3900 CONNECT login.live.com:443 - HIER_NONE/- text/html
1762770001.100 12 10.0.0.5 TCP_DENIED/403 3900 CONNECT login.live.com:443 - HIER_NONE/- text/html
1762770002.100 12 10.0.0.6 TCP_DENIED/403 3900 CONNECT news.bbc.co.uk:443 - HIER_NONE/- text/html
1762770003.100 80 10.0.0.6 TCP_TUNNEL/200 5100 CONNECT graph.microsoft.com:443 - HIER_DIRECT/20.190.1.1 -
1762770004.100 12 10.0.0.7 TCP_DENIED/403 3900 GET http://ads.tracker.example.org/pixel.gif - HIER_NONE/- text/html
1762770005.100 12 10.0.0.7 TCP_DENIED/403 3900 CONNECT 203.0.113.9:443 - HIER_NONE/- text/html
garbage line
"""


@pytest.fixture
def settings(tmp_path):
    """Settings pointing at a temp dir, with a fake apply helper that copies the staged list live."""
    live = tmp_path / "allowed_paw.acl"
    live.write_text(".microsoft.com\n.windowsupdate.com\nnot a domain!\n")
    hidden = tmp_path / "hidden_domains.txt"
    hidden.write_text(".doubleclick.net\n")
    log = tmp_path / "access.log"
    log.write_text(LOG)
    fake_apply = tmp_path / "fake-apply.sh"
    fake_apply.write_text(f"#!/bin/sh\n[ -e {tmp_path}/fail ] && {{ echo 'squid said no' >&2; exit 2; }}\n"
                          f"cp {tmp_path}/data/staging.acl {live}\necho applied\n")
    fake_apply.chmod(0o755)
    s = Settings()
    s.data_dir = str(tmp_path / "data")
    s.squid_acl = str(live)
    s.squid_log = str(log)
    s.legacy_hidden_list = str(hidden)
    s.apply_cmd = str(fake_apply)
    s.session_secret = "test-secret"
    s.entra_tenant_id = "tenant-1"
    s.entra_client_id = "client-1"
    s.entra_client_secret = "secret-1"
    s.required_role = "PAWProxyPilot.Admin"
    s.test_mode = True
    Path(s.data_dir).mkdir()
    squid._cache.clear()
    return s
