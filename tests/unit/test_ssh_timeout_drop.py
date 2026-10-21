import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from interceptor.ssh_proxy import SSHGuardSession
from interceptor.session_store import SessionStore


@pytest.mark.asyncio
async def test_simulate_network_timeout_drop():
    chan = MagicMock()
    conn = MagicMock()
    chan.get_connection.return_value = conn
    conn.is_closing.return_value = False

    backend_conn = MagicMock()
    backend_chan = MagicMock()
    backend_chan.is_closing.return_value = False

    store = MagicMock(spec=SessionStore)
    nft = MagicMock()
    classifier = MagicMock()
    decoy_mgr = MagicMock()

    session = SSHGuardSession(
        target_host="127.0.0.1",
        target_port=2200,
        session_id="sess_insider_1",
        src_ip="10.10.2.15",
        store=store,
        nft=nft,
        classifier=classifier,
        decoy_mgr=decoy_mgr,
        is_decoy=False,
        auth_username="marcus.vance",
        auth_password="password",
        real_conn=backend_conn,
    )
    session.chan = chan
    session.backend_chan = backend_chan

    # Verify initial state
    assert not getattr(session, "_is_dropping", False)

    # Trigger timeout drop with patched sleep to avoid waiting real time
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await session._simulate_network_timeout_drop()
        mock_sleep.assert_awaited_once_with(2.5)

    # 1. Backend channel closed quietly
    backend_chan.close.assert_called_once()

    # 2. Dropping flag is set
    assert session._is_dropping is True

    # 3. Transport connection closed abruptly
    conn.close.assert_called_once()

    # 4. Keystrokes during drop are ignored
    backend_chan.reset_mock()
    session.data_received(b"ls\n", 0)
    backend_chan.write.assert_not_called()
