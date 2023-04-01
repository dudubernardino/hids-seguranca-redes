import pandas as pd
import glob
from pygtrie import Trie

n = 8
f = 5

# Construa a árvore trie de system calls normais
normal_trie = Trie()
for filepath in glob.iglob("Attack_Data_Master/*/*.txt", recursive=True):
    with open(filepath) as current_file:
        for current_trace in current_file:
            for i in range(len(current_trace) - n):
                current_ngram = current_trace[i:i+n]
                normal_trie[current_ngram] = normal_trie.get(current_ngram, 0) + 1

# Verifique os arquivos de dados de teste em busca de intrusos
intrusions = []
for filepath in glob.iglob("Training_Data_Master/*.txt", recursive=True):
    with open(filepath) as current_file:
        for current_trace in current_file:
            current_trace_intrusions = []
            for i in range(len(current_trace) - n):
                current_ngram = current_trace[i:i+n]
                if normal_trie.get(current_ngram, 0) < f:
                    current_trace_intrusions.append(current_ngram)
            if len(current_trace_intrusions) > 0:
                intrusions.append([current_trace.strip(), current_trace_intrusions])

# Crie um dataframe com as informações das intrusões
intrusion_df = pd.DataFrame(intrusions, columns=['System Calls', 'Intrusions'])

print(intrusion_df)
