"""Bring! Shopping List MCP Server for Prefect Horizon (FastMCP)."""

import os
import json

import aiohttp
from bring_api import Bring, BringItemOperation
from fastmcp import FastMCP

mcp = FastMCP("bring-mcp")

_session: aiohttp.ClientSession | None = None
_bring: Bring | None = None


async def get_bring() -> Bring:
    """Get or create an authenticated Bring client."""
    global _session, _bring

    mail = os.environ.get("MAIL", "")
    pw = os.environ.get("PW", "")
    if not mail or not pw:
        raise RuntimeError("MAIL and PW environment variables are required")

    if _session is None or _session.closed:
        _session = aiohttp.ClientSession()
    if _bring is None:
        _bring = Bring(_session, mail, pw)
        await _bring.login()
    return _bring


def _json(data: object) -> str:
    """Serialize response data to JSON string."""
    if hasattr(data, "__dict__"):
        return json.dumps(data.__dict__, default=str, ensure_ascii=False)
    return json.dumps(data, default=str, ensure_ascii=False)


# ── List Tools ──────────────────────────────────────────────


@mcp.tool
async def load_lists() -> str:
    """Load all shopping lists from Bring!"""
    bring = await get_bring()
    result = await bring.load_lists()
    return _json(result)


# ── Item Tools ──────────────────────────────────────────────


@mcp.tool
async def get_items(list_uuid: str) -> str:
    """Get all items from a specific shopping list."""
    bring = await get_bring()
    result = await bring.get_list(list_uuid)
    return _json(result)


@mcp.tool
async def get_items_details(list_uuid: str) -> str:
    """Get details for items in a list."""
    bring = await get_bring()
    result = await bring.get_all_item_details(list_uuid)
    return _json(result)


@mcp.tool
async def save_item(list_uuid: str, item_name: str, specification: str = "") -> str:
    """Save an item to a shopping list. Use 'specification' for details like quantity (e.g. item_name='Milk', specification='2 liters')."""
    bring = await get_bring()
    await bring.save_item(list_uuid, item_name, specification)
    return f"Item saved: {item_name}" + (f" ({specification})" if specification else "")


@mcp.tool
async def save_item_batch(list_uuid: str, items: list[dict]) -> str:
    """Save multiple items to a shopping list. Each dict should have 'item_name' and optionally 'specification'."""
    bring = await get_bring()
    saved = []
    for item in items:
        name = item["item_name"]
        spec = item.get("specification", "")
        await bring.save_item(list_uuid, name, spec or "")
        saved.append(name)
    return f"Batch items saved: {', '.join(saved)}"


@mcp.tool
async def remove_item(list_uuid: str, item_name: str) -> str:
    """Remove an item from a specific shopping list."""
    bring = await get_bring()
    await bring.remove_item(list_uuid, item_name)
    return f"Item removed: {item_name}"


@mcp.tool
async def complete_item(list_uuid: str, item_name: str) -> str:
    """Move an item from a shopping list to the recently used / completed items list."""
    bring = await get_bring()
    await bring.complete_item(list_uuid, item_name)
    return f"Item completed: {item_name}"


@mcp.tool
async def delete_multiple_items(list_uuid: str, item_names: list[str]) -> str:
    """Delete multiple items from a specific shopping list by their names."""
    bring = await get_bring()
    from bring_api import BringItem

    bring_items = [BringItem(itemId=name) for name in item_names]
    await bring.batch_update_list(list_uuid, bring_items, BringItemOperation.REMOVE)
    return f"Multiple items deleted: {', '.join(item_names)}"


# ── User Tools ──────────────────────────────────────────────


@mcp.tool
async def get_list_users(list_uuid: str) -> str:
    """Get all users associated with a specific shopping list."""
    bring = await get_bring()
    result = await bring.get_list_users(list_uuid)
    return _json(result)


@mcp.tool
async def get_user_settings() -> str:
    """Get the settings for the current authenticated user."""
    bring = await get_bring()
    result = await bring.get_all_user_settings()
    return _json(result)


@mcp.tool
async def get_default_list() -> str:
    """Get the UUID of the default shopping list for the authenticated user. Use this if the user does not ask for a special list."""
    bring = await get_bring()
    settings = await bring.get_all_user_settings()
    if hasattr(settings, "usersettings") and isinstance(settings.usersettings, list):
        for setting in settings.usersettings:
            key = setting.get("key") if isinstance(setting, dict) else getattr(setting, "key", None)
            if key == "defaultListUUID":
                value = setting.get("value") if isinstance(setting, dict) else getattr(setting, "value", None)
                return str(value)
    raise ValueError("Default list UUID not found in user settings.")
