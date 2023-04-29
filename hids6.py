import os


# Define uma classe Trie que implementa uma árvore trie
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_word = False

# Classe Trie que implementa uma árvore trie
class Trie:
    def __init__(self):
        self.root = TrieNode()

    # Método para inserir uma palavra na árvore trie
    def insert(self, word):
        node = self.root
        for char in word:
            # Se um caractere não está na lista de filhos de um nó, adiciona ele
            if char not in node.children:
                node.children[char] = TrieNode()
            # Move o ponteiro do nó para o filho com o caractere atual
            node = node.children[char]
        # Quando chegar ao final da palavra, define o is_word como True
        node.is_word = True

    # Método para buscar uma palavra na árvore trie
    def search(self, word):
        node = self.root
        for char in word:
            # Se um caractere não está na lista de filhos de um nó, a palavra não está na árvore
            if char not in node.children:
                return False
            # Move o ponteiro do nó para o filho com o caractere atual
            node = node.children[char]
        # Retorna True se o nó atual representa o final de uma palavra
        return node.is_word

# Método para ler sequências de um diretório
# Como a pasta Attack_Data_Master possui outros diretórios diferente de Training_Data_Master e Validation_Data_Master, o código abaixo verifica se é um diretório ou não para recuperar os dados dos arquivos com extensão .txt. Caso não seja diretório o método faz a mesma ação de recuperar os dados.
def read_sequences_from_directory(directory_path, valid_extensions=[".txt"]):
    sequences = []
    for dirpath, dirnames, filenames in os.walk(directory_path):
        for filename in filenames:
            ext = os.path.splitext(filename)[1]
            if ext not in valid_extensions:
                continue
            file_path = os.path.join(dirpath, filename)
            with open(file_path) as f:
                for line in f:
                    sequence = line.strip().split()
                    sequences.append(sequence)
    return sequences


# Diretórios dos dados
TRAINING_DIR = 'Training_Data_Master'
ATTACK_DIR = 'Attack_Data_Master'
VALIDATION_DIR = 'Validation_Data_Master'

# Hiperparâmetros do algoritmo
n = 2
f = 5

# Pré-processamento dos dados
training_sequences = read_sequences_from_directory(TRAINING_DIR)
validation_sequences = read_sequences_from_directory(VALIDATION_DIR)
attack_sequences = read_sequences_from_directory(ATTACK_DIR)

# Fase de treinamento do algoritmo
trie = Trie()
for sequence in training_sequences:
    for i in range(len(sequence) - n + 1):
        subsequence = tuple(sequence[i:i+n])
        trie.insert(subsequence)

# Fase de teste do algoritmo com dados de ataque
for i, sequence in enumerate(attack_sequences):
    detected_subsequences = set()
    for j in range(len(sequence) - n + 1):
        subsequence = tuple(sequence[j:j+n])
        for k in range(n):
            if trie.search(subsequence[k:]):
                detected_subsequences.add(subsequence[k:])
        # verifica a frequência de cada subsequência detectada
        for subseq in detected_subsequences:
            freq = sum([1 for l in range(len(sequence) - n + 1)
                       if tuple(sequence[l:l+n]).count(subseq) > 0])
            if freq >= f and subseq not in detected_subsequences:
                detected_subsequences.add(subseq)
        if len(detected_subsequences) > 0:
            print(f"Sequência {i+1}")
            print("Ataque detectado na sequência:")
            # converter a sequência em string
            sequence_str = ' '.join(str(elem) for elem in sequence)
            for subsequence in detected_subsequences:
                # converter a subsequência em string
                subseq_str = ' '.join(str(elem) for elem in subsequence)
                # destacar a subsequência na sequência
                sequence_str = sequence_str.replace(
                    subseq_str, f"\033[1;31;40m{subseq_str}\033[0m")
            print(sequence_str)
            print()
            break  # interrompe a busca assim que uma sequência é detectada
    else:  # se o loop for terminar sem ter encontrado um ataque
        print(f"Sequência {i+1}")
        print("Ataque não detectado na sequência:")
        # converter a sequência em string
        sequence_str = ' '.join(str(elem) for elem in sequence)
        print(sequence_str)
        print()
