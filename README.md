## TD Ransomware

# Question 1 

L'algorithme de chiffrement utilisé dans le fichier xorcrypt.py est le XOR (eXclusive OR). Il s'agit d'un chiffrement par flot, où chaque bit de données est combiné avec un bit de la clé à l'aide de l'opération XOR. La clé est répétée en boucle pour s'adapter à la longueur des données.

Cet algorithme n'est pas robuste pour plusieurs raisons:

    Si la clé est plus courte que les données, elle est répétée, ce qui crée des motifs récurrents qui peuvent être exploités pour casser le chiffrement.
    Si la clé est utilisée pour chiffrer plusieurs messages, un attaquant peut appliquer des techniques d'analyse de fréquence pour identifier des correspondances et déterminer la clé.
    Si un attaquant connaît une partie du texte en clair et la version chiffrée correspondante, il peut facilement déterminer la clé en appliquant à nouveau l'opération XOR entre le texte en clair et le texte chiffré.

# Question 2

L'algorithme XOR n'est pas considéré comme étant particulièrement robuste, car il est vulnérable à plusieurs types d'attaques, telles que l'attaque par force brute, l'attaque par analyse de fréquence et l'attaque par clair connu (known-plaintext attack).Les fonctions de dérivation de clé (KDF) sont spécialement conçues pour créer des clés cryptographiques à partir de données secrètes, comme les mots de passe ou les clés privées. PBKDF2HMAC est une KDF basée sur HMAC et il est conçu pour résister aux attaques par force brute et attaques par dictionnaire.

# Question 3 

Il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent pour éviter de répéter l'opération de création et d'enregistrement des éléments cryptographiques et de leur envoi au CNC. Si un fichier token.bin existe déjà, cela signifie que les éléments cryptographiques ont déjà été générés et enregistrés localement, et qu'ils ont probablement déjà été envoyés au CNC. Dans ce cas, il n'est pas nécessaire de répéter l'opération, et cela permet d'économiser des ressources et d'éviter des problèmes potentiels liés à la création de plusieurs fichiers token.bin.

# Question 4

Pour vérifier que la clé est correcte, vous pouvez dériver une clé candidate à partir du sel et de la clé candidate et comparer cette clé dérivée avec la clé stockée. Si les deux clés dérivées correspondent, cela signifie que la clé candidate est correcte.