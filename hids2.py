import pandas as pd
import glob

known_attacks = []

# Recursively add attack traces to known attacks
for filepath in glob.iglob("Attack_Data_Master/*/*.txt", recursive=True):
    with open(filepath) as current_attack:
        for line in current_attack:
            known_attacks.append(line.strip())

attack_counter = 0
trace_list = []

# Recursively check files in validation data for each attack
for filepath in glob.iglob("Training_Data_Master/*.txt", recursive=True):
    with open(filepath) as current_file:
        for current_trace in current_file:
            trace_list.append([current_trace.strip(), 0])

for current_trace in trace_list:
    for attack_trace in known_attacks:
        if attack_trace in current_trace[0]:
            current_trace[1] += 1
            print("Found attack in", filepath, "!")
            print("Attack trace:", attack_trace)
            print("Data trace:", current_trace)
            attack_counter += 1

Traces = pd.DataFrame(trace_list, columns=['System Calls', 'Malicious'])

print(Traces.sort_values(by=['Malicious'])[-30:])

print('Total Attacks found:', attack_counter)