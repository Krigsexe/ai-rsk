# SAFE: subprocess without shell, arguments as list
import subprocess

subprocess.run(["convert", filename])
subprocess.run(["rm", validated_path], check=True)
result = subprocess.check_output(["cat", safe_path])
