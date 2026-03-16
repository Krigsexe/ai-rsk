# VULNERABLE: shell=True enables command injection
import subprocess
import os

subprocess.run(f"convert {filename}", shell=True)
subprocess.call("ls -la " + user_input, shell=True)
os.system(f"rm {path}")
os.popen(f"cat {filename}")
