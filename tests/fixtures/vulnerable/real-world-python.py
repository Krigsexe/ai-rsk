# =============================================================================
# REAL-WORLD VULNERABLE PATTERNS — PYTHON
# =============================================================================
# Sources:
# - Unit42 Palo Alto (2025): RCE in AI/ML Python libraries via pickle
# - JFrog (2025): 3 zero-day PickleScan bypass CVEs (CVE-2025-10157, CVSS 9.3)
# - Reversing Labs (2025): Malicious pickle files on Hugging Face (reverse shell)
# - NVIDIA CVE-2025-23304 (NeMo pickle vuln, High severity)
# - Salesforce CVE-2026-22584 (pickle in AI pipeline, High severity)
# - CVE-2020-1747 (PyYAML arbitrary code execution)
# - CWE Top 25:2025 #5: OS Command Injection
# =============================================================================

# --- PICKLE_LOAD: Arbitrary code execution via deserialization ---
# Real pattern: ML model loading from untrusted source (Hugging Face, user upload)
import pickle
model = pickle.load(open("model.pkl", "rb"))

# Real pattern: API endpoint accepting pickled data (Palo Alto Unit42 research)
import pickle
data = pickle.loads(request.get_data())

# Real pattern: cPickle (C implementation, same vulnerability)
import cPickle
result = cPickle.loads(raw_bytes)

# Real pattern: shelve (uses pickle internally)
import shelve
db = shelve.open("cache.db")

# --- YAML_UNSAFE: Arbitrary Python object instantiation ---
# Real pattern: yaml.load with unsafe Loader (CVE-2020-1747)
import yaml
config = yaml.load(open("config.yml"), Loader=yaml.Loader)

# Real pattern: yaml.unsafe_load (explicitly dangerous)
import yaml
data = yaml.unsafe_load(user_input)

# Real pattern: FullLoader (can instantiate some Python objects)
import yaml
data = yaml.load(content, Loader=yaml.FullLoader)

# --- SUBPROCESS_SHELL: OS command injection ---
# Real pattern: AI-generated file conversion code (DryRun Security 2026)
import subprocess
subprocess.run(f"convert {user_file} output.pdf", shell=True)

# Real pattern: AI-generated backup script
import subprocess
subprocess.call("tar -czf backup.tar.gz " + directory, shell=True)

# Real pattern: os.system with user input (CWE-78)
import os
os.system(f"ping -c 1 {hostname}")

# Real pattern: os.popen for command output
import os
output = os.popen(f"nslookup {domain}").read()
