# SAFE: Using JSON instead of pickle
import json

with open('data.json') as f:
    data = json.load(f)
