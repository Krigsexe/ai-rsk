# SAFE: yaml.safe_load
import yaml

data = yaml.safe_load(content)
data2 = yaml.load(content, Loader=yaml.SafeLoader)
