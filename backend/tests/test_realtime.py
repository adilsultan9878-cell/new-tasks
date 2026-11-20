import pytest
from starlette.websockets import WebSocketDisconnect

from app.core.config import get_settings
from tests.conftest import Fleet, make_client

WS = "/api/v1/ws"


def _auth(ws, token, org_id):
    ws.send_json({"type": "auth", "token": token, "org_id": org_id})
    return ws.receive_json()


def test_stream_requires_valid_token(fleet):
    with make_client().websocket_connect(WS) as ws:
        ws.send_json({"type": "auth", "token": "nope", "org_id": fleet.org_id})
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
    assert exc.value.code == 4401


def test_stream_rejects_non_members(fleet, account_factory):
    stranger = account_factory("stranger")
    with make_client().websocket_connect(WS) as ws:
        ws.send_json({"type": "auth", "token": stranger.token, "org_id": fleet.org_id})
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
    assert exc.value.code == 4403


def test_stream_rejects_foreign_origins(fleet):
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        make_client().websocket_connect(WS, headers={"origin": "https://evil.example"}) as ws,
    ):
        ws.receive_json()
    assert exc.value.code == 4403


def test_stream_delivers_tenant_events_after_commit(fleet, account_factory):
    other = Fleet(account_factory("other"), "Other")
    token = fleet.enroll()["device_token"]
    with make_client().websocket_connect(WS, headers={"origin": "http://localhost:5173"}) as ws:
        assert _auth(ws, fleet.owner.token, fleet.org_id)["type"] == "ready"
        other.enroll("noise")  # another tenant's activity must not leak into this stream
        fleet.device_post(
            token,
            "/events",
            {
                "events": [
                    {
                        "event_type": "malware.detected",
                        "category": "malware",
                        "severity": "high",
                        "title": "EICAR test file",
                    }
                ]
            },
        )
        kinds = []
        while "alert.created" not in kinds or "event.created" not in kinds:
            msg = ws.receive_json()
            kinds.append(msg["type"])
            if msg["type"] == "event.created":
                assert msg["data"]["title"] == "EICAR test file" and msg["data"]["device_name"] == "ws-01"
        assert all(k in {"event.created", "alert.created", "device.updated", "ping"} for k in kinds)


def test_stream_closes_after_logout(fleet, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ws_ping_interval_seconds", 0.05)
    monkeypatch.setattr(settings, "ws_revalidate_seconds", 0)
    with make_client().websocket_connect(WS) as ws:
        assert _auth(ws, fleet.owner.token, fleet.org_id)["type"] == "ready"
        fleet.owner.client.post("/api/v1/auth/logout", headers={"X-Requested-With": "sentinel-x"})
        with pytest.raises(WebSocketDisconnect) as exc:
            for _ in range(200):
                ws.receive_json()
    assert exc.value.code == 4401
