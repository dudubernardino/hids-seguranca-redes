import pandas as pd
import glob
from pygtrie import Trie

def get_n_grams(trace, n):
    """Retorna uma lista de todos os n-grams de tamanho n presentes em trace."""
    trace_array = [trace]
    split_traces = trace_array[0].split() 
    n_grams = []

    for i in range(0, len(split_traces), n):
        join_traces = ' '.join(split_traces[i:i+n])
        n_grams.append(join_traces)


    # print('n_grams', n_grams)
    return n_grams

def train(sequences, n, f):
    """Treina o algoritmo com as sequências dadas e retorna um dicionário com as subsequências únicas."""
    subsequences = {}
    for sequence in sequences:
        n_grams = get_n_grams(sequence, n)
        for n_gram in set(n_grams):
            if n_grams.count(n_gram) >= f:
                if n_gram not in subsequences:
                    subsequences[n_gram] = 1
                else:
                    subsequences[n_gram] += 1
    return subsequences

def test(trace, subsequences):
    """Testa o algoritmo com a sequência dada e retorna True se um intruso foi detectado."""
    n_grams = get_n_grams(trace, n)
    for i in range(len(trace) - n + 1):
        n_gram = trace[i:i+n]
        if n_gram not in subsequences:
            return True
    return False

# Construa a árvore trie de ataques conhecidos
attack_trie = Trie()
for filepath in glob.iglob("Attack_Data_Master/*/*.txt", recursive=True):
    with open(filepath) as current_attack:
        for line in current_attack:
            attack_trie[line.strip()] = True

# Defina os valores de n e f
n = 2
f = 5

# Treine o algoritmo com as sequências de treinamento
normal_traces = []
for filepath in glob.iglob("Training_Data_Master/*.txt", recursive=True):
    with open(filepath) as current_file:
        for current_trace in current_file:
            normal_traces.append(current_trace.strip())
subsequences = train(normal_traces, n, f)

# Teste o algoritmo com as sequências de teste
trace_list = []
attack_counter = 0
for filepath in glob.iglob("Validation_Data_Master/*.txt", recursive=True):
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
                    print()
                    break
            if not found_attack:
                if test(current_trace.strip(), subsequences):
                    trace_list.append([current_trace.strip(), 1])
                    attack_counter += 1
                    print("Found attack in", filepath, "!")
                    print("Data trace:", current_trace.strip())
                    print()
                else:
                    trace_list.append([current_trace.strip(), 0])

Traces = pd.DataFrame(trace_list, columns=['System Calls', 'Malicious'])

print(Traces.sort_values(by=['Malicious'])[-30:])
print('Total Attacks found:', attack_counter)
