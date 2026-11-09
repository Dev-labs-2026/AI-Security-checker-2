import os
from motor.motor_asyncio import AsyncIOMotorClient

_client = None
_col = None


async def init_db():
    """Connect to MongoDB. If it's unavailable the app still works, just without history."""
    global _client, _col
    uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    try:
        _client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=3000)
        await _client.admin.command("ping")
        _col = _client[os.getenv("MONGO_DB", "ai_security_checker")]["scans"]
        await _col.create_index([("scanned_at", -1)])
        await _col.create_index("host")
        print("[db] MongoDB connected")
    except Exception as e:
        _col = None
        print(f"[db] MongoDB unavailable ({e}). Running without persistence.")


def is_connected() -> bool:
    return _col is not None


async def save_scan(doc: dict):
    if _col is None:
        return None
    try:
        res = await _col.insert_one(dict(doc))  # copy, so _id doesn't leak into the response
        return str(res.inserted_id)
    except Exception as e:
        print(f"[db] save failed: {e}")
        return None


async def get_history(limit: int = 15):
    if _col is None:
        return []
    try:
        cursor = (
            _col.find({}, {"url": 1, "host": 1, "score": 1, "verdict": 1, "scanned_at": 1})
            .sort("scanned_at", -1)
            .limit(limit)
        )
        items = []
        async for d in cursor:
            d["id"] = str(d.pop("_id"))
            items.append(d)
        return items
    except Exception as e:
        print(f"[db] history failed: {e}")
        return []