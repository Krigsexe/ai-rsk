# =============================================================================
# REAL-WORLD SAFE PATTERNS — PYTHON
# =============================================================================
# Secure alternatives for each vulnerable pattern above.
# =============================================================================

# --- Safe deserialization: JSON instead of pickle ---
import json
with open("model_config.json") as f:
    config = json.load(f)

# --- Safe deserialization: MessagePack ---
import msgpack
data = msgpack.unpackb(raw_bytes, raw=False)

# --- Safe deserialization: PyTorch with weights_only ---
import torch
model = torch.load("model.pt", weights_only=True)

# --- Safe YAML loading ---
import yaml
config = yaml.safe_load(open("config.yml"))
data = yaml.load(content, Loader=yaml.SafeLoader)

# --- Safe subprocess: no shell, arguments as list ---
import subprocess
subprocess.run(["convert", user_file, "output.pdf"])
subprocess.run(["tar", "-czf", "backup.tar.gz", directory], check=True)
result = subprocess.check_output(["ping", "-c", "1", validated_host])
