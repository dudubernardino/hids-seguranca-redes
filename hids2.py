from pygtrie import Trie

import os

# Read in all sys call traces as tuples in the 'traces' list: (type,list of sys call sequence)
traces = []
# Imports the attack system call traces to the list
atkbase = "/home/eduardo/desktop/hids-seguranca-redes/Attack_Data_Master/"
types = ['Adduser', 'Hydra_FTP', 'Hydra_SSH',
         'Java_Meterpreter', 'Meterpreter', 'Web_Shell']
for elem in types:
    for i in range(1, 11):
        path = atkbase + elem + "_" + str(i)
        os.chdir(path)

        def read_files(file_path):
            with open(file_path, 'r') as file:
                mystring = file.read()
                x = mystring.split()
                traces.append(('1', x))
        # Iterate over all the files in the directory
        for file in os.listdir():
            if file.endswith('.txt'):
                # Create the filepath of particular file
                file_path = f"{path}/{file}"
                read_files(file_path)

# Imports (appends) the training/test data folders' system call traces
normal = ("/home/eduardo/desktop/hids-seguranca-redes/Training_Data_Master",
          "/home/eduardo/desktop/hids-seguranca-redes/Validation_Data_Master")
for elem in normal:
    os.chdir(elem)

    def read_files(file_path2):
        with open(file_path2, 'r') as file:
            mystring = file.read()
            x = mystring.split()
            traces.append(('0', x))
    for file in os.listdir():
        # Check whether file is in text format or not
        if file.endswith(".txt"):
            file_path2 = f"{elem}/{file}"
            # call read text file function
            read_files(file_path2)

# Desired n-gram length(s)
n = [1, 2]

# Create a dictionary of features (keys are the unique system calls, values are the number of system calls that have that particular system call)
featDict = dict()

# Iterates through all sys call traces to build feature dictionary
for elem in traces:
    # Iterates through each system call of a particular trace
    for i in range(len(elem[1])):
        # Creates n-gram(s) of subsequent system calls
        for j in n:
            if i+j <= len(elem[1]):
                ngram = tuple(elem[1][i:i+j])
                if ngram in featDict:
                    featDict[ngram] += 1
                else:
                    featDict[ngram] = 1

# Determine the feature dictionary elements that occur with frequency > f
f = 5
ngrams = []
for k, v in featDict.items():
    if v >= f:
        ngrams.append(k)

# Use trie data structure to store n-grams
root = Trie()
for elem in traces:
    for i in range(len(elem[1])):
        for j in n:
            if i+j <= len(elem[1]):
                ngram = tuple(elem[1][i:i+j])
                if ngram in ngrams:
                    root[ngram] = 0

# Loop over test sequence(s) to identify anomalous n-gram(s)
testFile = "/home/eduardo/desktop/hids-seguranca-redes/Validation_Data_Master/UVD-0010.txt"
with open(testFile, 'r') as file:
    mystring = file.read()
    testSeq = mystring.split()

anomalous = []
for i in range(len(testSeq)):
    for j in n:
        if i+j <= len(testSeq):
            ngram = tuple(testSeq[i:i+j])
            if ngram not in root:
                anomalous.append(ngram)
anomalous = list(set(anomalous))

if len(anomalous) >= f:
    print("Anomaly detected!")
