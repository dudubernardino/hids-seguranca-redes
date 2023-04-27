import os
from pygtrie import Trie
import time


def get_n_grams(trace, n_values):
    """Returns a list of all n-grams of sizes in n_values present in trace."""
    trace_array = [trace]
    split_traces = ' '.join(trace_array[0]).split()
    n_grams = []

    for n in n_values:
        for i in range(0, len(split_traces) - n + 1):
            join_traces = ' '.join(split_traces[i:i+n])
            n_grams.append(join_traces)

    return n_grams


def train(sequences, n_values, f):
    """Trains the algorithm with the given sequences and returns a dictionary with the unique subsequences."""
    print("Training...")
    subsequences = Trie()
    for sequence in sequences:
        n_grams = get_n_grams(sequence, n_values)
        for n_gram in set(n_grams):
            if n_grams.count(n_gram) >= f:
                subsequences[n_gram] = True
    print("Training complete.")
    return subsequences


def test(trace, subsequences, n_values):
    """Tests the algorithm with the given trace and returns True if an intruder was detected."""
    print("Testing...")
    n_grams = get_n_grams(trace, n_values)
    for i in range(len(n_grams)):
        if not subsequences.has_subtrie(n_grams[i]):
            attack_trace = ' '.join(trace[i:])
            print("Found attack in trace: ", attack_trace)
            print()
            print("Data trace: ", ' '.join(trace))
            return True
    print("Testing complete.")
    return False


def calcular_eficiencia(tempo_total, num_traces):
    tempo_medio = tempo_total / num_traces
    return tempo_medio


# Read in all system call traces as tuples in the 'traces' list: (type, list of sys call sequence)
traces = []
# Imports the attack system call traces to the list
atkbase = "/home/eduardo/desktop/hids-seguranca-redes/Attack_Data_Master/"
types = ['Adduser', 'Hydra_FTP', 'Hydra_SSH',
         'Java_Meterpreter', 'Meterpreter', 'Web_Shell']
for elem in types:
    for i in range(1, 11):
        path = atkbase + elem + "_" + str(i)
        os.chdir(path)

        for file in os.listdir():
            if file.endswith('.txt'):
                file_path = f"{path}/{file}"
                with open(file_path, 'r') as file:
                    mystring = file.read()
                    trace = mystring.split()
                    traces.append(('1', trace))

# Imports (appends) the training/test data folders' system call traces
normal = ("/home/eduardo/desktop/hids-seguranca-redes/Training_Data_Master",
          "/home/eduardo/desktop/hids-seguranca-redes/Validation_Data_Master")
for elem in normal:
    os.chdir(elem)

    for file in os.listdir():
        if file.endswith(".txt"):
            file_path = f"{elem}/{file}"
            with open(file_path, 'r') as file:
                mystring = file.read()
                trace = mystring.split()
                traces.append(('0', trace))

# Desired n-gram length(s)
n_values = [2]

# Train the algorithm
f = 5

start_time = time.time()
subsequences = train([trace[1] for trace in traces], n_values, f)
end_time = time.time()
tempo_treinamento = end_time - start_time
num_traces_treinamento = len(traces)


# Test the algorithm and measure efficiency
anomalous_traces = []
num_traces_teste = 0
tempo_teste = 0

validation_data_path = "/home/eduardo/desktop/hids-seguranca-redes/Validation_Data_Master/"
for filename in os.listdir(validation_data_path):
    if filename.endswith(".txt"):
        with open(os.path.join(validation_data_path, filename), 'r') as file:
            mystring = file.read()
            trace = mystring.split()
            start_time = time.time()
            if test(trace, subsequences, n_values):
                print()
                print(f"Anomaly detected in {filename}!")
                print()
                anomalous_traces.append(filename)
            end_time = time.time()
            tempo_teste += end_time - start_time
            num_traces_teste += 1

# Print the efficiency metrics
tempo_total = tempo_treinamento + tempo_teste
num_traces_total = num_traces_treinamento + num_traces_teste
eficiencia = calcular_eficiencia(tempo_total, num_traces_total)

print(f"Tempo total de processamento: {tempo_total:.2f} segundos")
print(f"Número total de traces processados: {num_traces_total}")
print(f"Tempo médio de processamento por trace: {eficiencia:.4f} segundos")
