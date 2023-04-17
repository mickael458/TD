## TD Ransomware

# Question 1 

L'algorithme de chiffrement utilisé dans le fichier xorcrypt.py est le XOR (eXclusive OR). Il s'agit d'un chiffrement par flot, où chaque bit de données est combiné avec un bit de la clé à l'aide de l'opération XOR. La clé est répétée en boucle pour s'adapter à la longueur des données.

Cet algorithme n'est pas robuste pour plusieurs raisons:

    Si la clé est plus courte que les données, elle est répétée, ce qui crée des motifs récurrents qui peuvent être exploités pour casser le chiffrement.
    Si la clé est utilisée pour chiffrer plusieurs messages, un attaquant peut appliquer des techniques d'analyse de fréquence pour identifier des correspondances et déterminer la clé.
    Si un attaquant connaît une partie du texte en clair et la version chiffrée correspondante, il peut facilement déterminer la clé en appliquant à nouveau l'opération XOR entre le texte en clair et le texte chiffré.

# Question 2

Il est préférable d'utiliser un algorithme de dérivation de clé tel que PBKDF2HMAC plutôt que de hacher directement le sel et la clé. PBKDF2HMAC est conçu pour être lent et coûteux en termes de temps de calcul, ce qui rend les attaques par force brute moins efficaces. De plus, il permet un nombre configurable d'itérations, ce qui peut augmenter la sécurité en fonction des besoins. HMAC, d'un autre côté, est un algorithme de hachage à clé et ne serait pas adapté pour générer un sel et une clé sécurisés pour le chiffrement.

# Question 3 

Il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent pour éviter de répéter l'opération de création et d'enregistrement des éléments cryptographiques et de leur envoi au CNC. Si un fichier token.bin existe déjà, cela signifie que les éléments cryptographiques ont déjà été générés et enregistrés localement, et qu'ils ont probablement déjà été envoyés au CNC. Dans ce cas, il n'est pas nécessaire de répéter l'opération, et cela permet d'économiser des ressources et d'éviter des problèmes potentiels liés à la création de plusieurs fichiers token.bin.

# Question 4

Pour confirmer que la clé entrée est valide, on peut réaliser un processus de dérivation de clé en utilisant le sel. Ensuite, il suffit de comparer le résultat obtenu avec le token stocké. Si ces éléments correspondent, cela indique que la clé est correcte et peut être employée pour décoder les données.
