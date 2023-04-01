import pandas as pd
import glob
from pygtrie import Trie

# Construa a árvore trie de ataques conhecidos
attack_trie = Trie()
for filepath in glob.iglob("Attack_Data_Master/*/*.txt", recursive=True):
    with open(filepath) as current_attack:
        for line in current_attack:
            attack_trie[line.strip()] = True

attack_counter = 0
trace_list = []

# Verifique os arquivos de dados de treinamento em busca de cada ataque
for filepath in glob.iglob("Training_Data_Master/*.txt", recursive=True):
    with open(filepath) as current_file:
        for current_trace in current_file:
            # Pesquise na árvore trie se há um padrão de ataque na linha atual
            found_attack = False
            for i in range(len(current_trace)):
                if attack_trie.has_subtrie(current_trace[i:]):
                    trace_list.append([current_trace.strip(), 1])
                    found_attack = True
                    attack_counter += 1
                    print("Found attack in", filepath, "!")
                    print("Attack trace:", current_trace[i:].strip())
                    print("Data trace:", current_trace.strip())
                    break
            if not found_attack:
                trace_list.append([current_trace.strip(), 0])

Traces = pd.DataFrame(trace_list, columns=['System Calls', 'Malicious'])

print(Traces.sort_values(by=['Malicious'])[-30:])

print('Total Attacks found:', attack_counter)