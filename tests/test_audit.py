import json

from app.audit import AuditLog
from app.session_auth import Identity

ADMIN = Identity("22222222-2222-4222-8222-222222222222", "admin", "admin@example.com", "Ada", "Admin")


def test_admin_action_writes_one_json_line():
    lines = []
    AuditLog(write=lines.append, clock=lambda: 1_800_000_000).admin_action(
        action="disable",
        admin=ADMIN,
        result="ok",
        target_sub="11111111-1111-4111-8111-111111111111",
        target_email="pat@example.com",
    )
    assert len(lines) == 1 and "\n" not in lines[0]
    assert json.loads(lines[0]) == {
        "event": "admin_action",
        "action": "disable",
        "admin_sub": ADMIN.sub,
        "admin_email": "admin@example.com",
        "target_sub": "11111111-1111-4111-8111-111111111111",
        "target_email": "pat@example.com",
        "result": "ok",
        "timestamp": "2027-01-15T08:00:00+00:00",
    }


def test_previous_email_only_when_given():
    lines = []
    log = AuditLog(write=lines.append, clock=lambda: 0)
    log.admin_action(action="email", admin=ADMIN, result="ok", previous_email="old@example.com")
    log.admin_action(action="enable", admin=ADMIN, result="ok")
    assert json.loads(lines[0])["previous_email"] == "old@example.com"
    assert "previous_email" not in json.loads(lines[1])
