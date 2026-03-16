# VULNERABLE: pickle.load with untrusted data
import pickle

with open('data.pkl', 'rb') as f:
    data = pickle.load(f)

raw = request.get_data()
obj = pickle.loads(raw)
