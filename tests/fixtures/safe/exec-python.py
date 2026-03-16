# SAFE: No exec/eval with user input
import ast
result = ast.literal_eval(safe_string)
