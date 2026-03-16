# VULNERABLE: yaml.load with unsafe Loader
import yaml

data = yaml.load(content, Loader=yaml.Loader)
data2 = yaml.unsafe_load(raw_input)
