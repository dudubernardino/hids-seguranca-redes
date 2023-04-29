import os
from pygtrie import Trie
import time


def get_n_grams(trace, n_values):
    """Retorna uma lista de todos os n-gramas de tamanhos em n_values presentes em trace."""
    trace_array = [trace]
    split_traces = ' '.join(trace_array[0]).split()
    n_grams = []

    # Para cada tamanho de n-grama em n_values, gera todos os n-gramas possíveis e os adiciona à lista
    for n in n_values:
        for i in range(0, len(split_traces) - n + 1):
            join_traces = ' '.join(split_traces[i:i+n])
            n_grams.append(join_traces)

    return n_grams


def train(sequences, n_values, f):
    """Treina o algoritmo com as sequências dadas e retorna um dicionário com as subsequências únicas."""
    print("Treinando...")
    subsequences = Trie()

    # Para cada sequência, gera todos os n-gramas e adiciona as subsequências únicas que aparecem pelo menos f vezes ao dicionário
    for sequence in sequences:
        n_grams = get_n_grams(sequence, n_values)
        for n_gram in set(n_grams):
            if n_grams.count(n_gram) >= f:
                subsequences[n_gram] = True

    print("Treinamento completo.")
    return subsequences


def test(trace, subsequences, n_values):
    """Testa o algoritmo com o trace dado e retorna True se um intruso foi detectado."""
    print("Testando...")
    n_grams = get_n_grams(trace, n_values)

    # Verifica se cada n-grama está presente nas subsequências treinadas e, se não estiver, reporta um ataque
    for i in range(len(n_grams)):
        if not subsequences.has_subtrie(n_grams[i]):
            attack_trace = ' '.join(trace[i:])
            print("Ataque encontrado no trace: ", attack_trace)
            print()
            print("Trace de dados: ", ' '.join(trace))
            return True

    print("Teste completo.")
    return False


def calcular_eficiencia(tempo_total, num_traces_total):
    """Calcula a eficiência média do processamento por trace."""
    tempo_medio = tempo_total / num_traces_total
    return tempo_medio


# Lê todas as sequências de chamadas do sistema como tuplas na lista 'traces': (tipo, sequência de chamadas do sistema)
traces = []

# Importa as sequências de chamadas do sistema de ataque para a lista
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

# Importa os diretórios de treinamento/teste contendo traces do sistema
normal = ("/home/eduardo/desktop/hids-seguranca-redes/Training_Data_Master",
          "/home/eduardo/desktop/hids-seguranca-redes/Validation_Data_Master")
for elem in normal:
    os.chdir(elem)

    for file in os.listdir():
        if file.endswith(".txt"):
            file_path = f"{elem}/{file}"  # caminho completo para o arquivo
            with open(file_path, 'r') as file:
                mystring = file.read()
                trace = mystring.split()  # quebra a string do arquivo em palavras individuais
                # adiciona a tupla ('0', trace) à lista de traces
                traces.append(('0', trace))

# Comprimentos de n-gram(s) desejados
n_values = [2]

# Treina o algoritmo
f = 5  # parâmetro do algoritmo, definindo a frequência mínima necessária para uma subsequência ser considerada frequente

start_time = time.time()
# treina o algoritmo com os traces de treinamento e armazena as subsequências frequentes em 'subsequences'
subsequences = train([trace[1] for trace in traces], n_values, f)
end_time = time.time()
tempo_treinamento = end_time - start_time
num_traces_treinamento = len(traces)


# Testa o algoritmo e mede a eficiência
anomalous_traces = []  # armazena traces que foram detectados como anomalias
num_traces_teste = 0  # contador de traces testados
tempo_teste = 0

validation_data_path = "/home/eduardo/desktop/hids-seguranca-redes/Validation_Data_Master/"
for filename in os.listdir(validation_data_path):
    if filename.endswith(".txt"):
        with open(os.path.join(validation_data_path, filename), 'r') as file:
            mystring = file.read()
            trace = mystring.split()  # quebra a string do arquivo em palavras individuais
            start_time = time.time()
            # testa o trace usando as sequências frequentes
            if test(trace, subsequences, n_values):
                print()
                print(f"Anomalia detectada em {filename}!")
                print()
                # adiciona o nome do trace à lista de anomalias
                anomalous_traces.append(filename)
            end_time = time.time()
            tempo_teste += end_time - start_time
            num_traces_teste += 1  # incrementa o contador de traces testados

# Imprime as métricas de eficiência
tempo_total = tempo_treinamento + tempo_teste
num_traces_total = num_traces_treinamento + num_traces_teste
eficiencia = calcular_eficiencia(tempo_total, num_traces_total)

print(f"Tempo total de processamento: {tempo_total:.2f} segundos")
print(f"Número total de traces processados: {num_traces_total}")
print(f"Tempo médio de processamento por trace: {eficiencia:.4f} segundos")
