import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _get_state_path(config: dict) -> str:
    state_conf = config.get("State", {})
    path = state_conf.get("Path", "state.json")
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    return path

def load_state(config: dict) -> dict:
    path = _get_state_path(config)
    if not os.path.exists(path):
        return {
            "last_updated": None,
            "servers": {}
        }
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "last_updated": None,
            "servers": {}
        }

def save_state(config: dict, state: dict) -> None:
    path = _get_state_path(config)
    state["last_updated"] = datetime.utcnow().isoformat()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
