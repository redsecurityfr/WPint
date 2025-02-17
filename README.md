![Logo du projet](https://github.com/redsecurityfr/WPint/blob/main/WPINT.png)


# WPInt - Analyseur WordPress

WPInt est un outil d'analyse OSINT de CMS WordPress qui permet d'extraire et d'analyser les informations des utilisateurs WordPress, notamment les hashes Gravatar associés aux comptes et la recherche d'image avec EXIF.

## Fonctionnalités

- Extraction des utilisateurs WordPress via l'API REST
- Récupération et analyse des hashes Gravatar
- Déchiffrement optionnel des hashes via l'API hashes.com
- Support du mode asynchrone pour l'analyse de plusieurs domaines
- Extraction des données EXIF pertinentes des images
- Contournement des limitations de taux (optionnel)

## Prérequis

- Python 3.6 ou supérieur
- Les dépendances suivantes (installables via pip) :
  - requests>=2.31.0
  - tqdm>=4.66.1
  - termcolor>=2.4.0
  - piexif>=1.1.3

## Installation

1. Clonez ce dépôt
2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python WPInt.py [-h] [-d DOMAINS] [-l FILE] [-e] [-b] [--verbose] [--api-key]
```

### Arguments

- `-h, --help` : Affiche l'aide
- `-e`: Recherche EXIF sur le domaine
- `-d DOMAINS [DOMAINS ...]` : Liste des domaines WordPress à analyser
- `-l FILE` : Fichier contenant une liste de domaines (un par ligne)
- `-b, --bypass` : Active le contournement des limitations de taux
- `-v, --verbose` : Mode verbeux pour plus de détails
- `--api-key API_KEY` : Clé API hashes.com pour le déchiffrement des hashes

### Exemples

Analyser un seul domaine :
```bash
python WPInt.py -d example.wordpress.com
```


Analyser une liste de domaines depuis un fichier :
```bash
python WPInt.py -l domains.txt
```



