"""The combined server: toolset selection and the no-value-in, no-value-out contract."""

import pytest

from blind_vault_mcp import server

VALUE_LIKE = {"value", "secret", "token", "password", "master_password", "client_secret", "api_key"}


def names(toolsets):
    return {t.name for t in server.selected_tools(toolsets)}


def test_default_is_the_secrets_toolset_only():
    assert server.parse_toolsets(None) == ("secrets",)
    assert server.parse_toolsets(" ") == ("secrets",)
    assert names(("secrets",)) == {"list_collections", "list_items", "create_collection", "grant_reader",
                                   "set_secret", "delete_secret", "restore_info"}


def test_toolsets_are_parsed_in_a_fixed_order():
    assert server.parse_toolsets("send, VAULT") == ("vault", "send")
    assert server.parse_toolsets("all") == ("secrets", "vault", "send")


def test_a_typo_in_toolsets_stops_the_server():
    with pytest.raises(SystemExit, match="unknown toolset"):
        server.parse_toolsets("secrets,valut")


def test_the_legacy_folder_tools_are_not_served():
    # vw_set takes the value as an argument: it would put the secret through the chat
    assert not names(("secrets", "vault", "send")) & server.LEGACY_TOOLS


def test_send_is_separate_from_vault():
    assert not names(("vault",)) & server.SEND_TOOLS
    assert names(("send",)) == server.SEND_TOOLS


def test_no_tool_outside_send_takes_a_value_argument():
    for tool in server.selected_tools(("secrets", "vault")):
        params = set(tool.parameters.get("properties", {}))
        assert not params & VALUE_LIKE, f"{tool.name} takes {params & VALUE_LIKE}"


def test_the_combined_server_registers_every_selected_tool():
    app = server.build(("secrets", "vault", "send"))
    served = {t.name for t in app._tool_manager.list_tools()}
    assert served == names(("secrets", "vault", "send"))
    assert "without ever seeing a value" in app.instructions


def test_the_keyring_service_is_configurable(monkeypatch):
    from vw_server import client
    monkeypatch.delenv("VW_KEYRING_SERVICE", raising=False)
    assert client.keyring_service() == "vw-manager"
    monkeypatch.setenv("VW_KEYRING_SERVICE", "my-manager")
    assert client.keyring_service() == "my-manager"
