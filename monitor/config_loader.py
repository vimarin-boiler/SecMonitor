import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_config():
    config_path = os.path.join(BASE_DIR, "config", "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)
