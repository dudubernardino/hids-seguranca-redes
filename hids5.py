import os
from collections import defaultdict


class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_word = False


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_word = True

    def search(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                return False
            node = node.children[char]
        return node.is_word


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


def extract_ngrams(sequences, n, f):
    ngram_counts = defaultdict(int)
    for sequence in sequences:
        for i in range(len(sequence) - n + 1):
            ngram = tuple(sequence[i:i+n])
            ngram_counts[ngram] += 1

    frequent_ngrams = []
    for ngram, count in ngram_counts.items():
        if count >= f:
            frequent_ngrams.append(ngram)

    return frequent_ngrams


def build_trie(ngrams):
    trie = Trie()
    for ngram in ngrams:
        trie.insert(ngram)
    return trie


def detect_intrusions(sequences, trie, n, f):
    intrusions = []
    for sequence in sequences:
        for i in range(len(sequence) - n + 1):
            ngram = tuple(sequence[i:i+n])
            count = 0
            if trie.search(ngram):
                continue
            for j in range(i, len(sequence) - n + 1):
                if trie.search(sequence[j:j+n]):
                    count += 1
                if count >= f:
                    intrusion_trace = " ".join(str(x) for x in sequence[i:i+n])
                    intrusion_trace += " ..."
                    intrusion_trace += " ".join(str(x)
                                                for x in sequence[i+n:i+2*n])
                    intrusion_trace += " " if i + 2 * n < len(sequence) else ""
                    intrusion_trace += "..."
                    intrusions.append(sequence)
                    print(
                        f"Found attack in {'/'.join(sequence[0].split('/')[:-1])}/{sequence[0].split('/')[-1]}!")
                    print(f"Attack trace: {intrusion_trace}")
                    print(f"Data trace: {' '.join(str(x) for x in seq)}")
                    print()
                    break
                # else:
                #     # print(f"Normal data trace: {sequence}")
                #     print(f"Normal data trace: {seq}")
                #     print()
    return intrusions


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

# Treinamento do algoritmo com dados de treino
training_subsequences = extract_ngrams(training_sequences, n, f)
trie = build_trie(training_subsequences)

# Teste do algoritmo com dados de ataque
for seq in attack_sequences:
    test_subsequences = extract_ngrams([seq], n, f)
    detect_intrusions(test_subsequences, trie, n, f)
