# Projet de Sonification du Trafic Reseau (Python + Tshark + Pure Data)

Ce projet transforme du trafic reseau en evenements sonores afin de faciliter la perception de comportements normaux et suspects en temps reel.

Version simple : au lieu de lire des lignes techniques difficiles, on "entend" le comportement du reseau.
- trafic normal = son plus calme ;
- trafic anormal (pic, scan, flood) = son plus present ou plus agressif.

Le systeme repose sur :
- un script Python d'analyse continue (`realtime_tshark_sonification.py`) ;
- `tshark` (capture paquets en ligne de commande) ;
- un patch Pure Data (`pd_ping_volume.pd`) pour la synthese audio.

## 1) Objectif 

Ce travail a pour objectif :
- introduire les notions de cybersecurite et supervision reseau ;
- relier l'analyse de donnees a la creation sonore ;
- proposer un dispositif de demonstration interactif.


## 1.1) Mini glossaire

- **Trafic reseau** : tout ce qui circule entre votre machine et internet.
- **Paquet** : petit bloc de donnees qui transite sur le reseau.
- **Interface reseau** : "porte d'entree/sortie" de votre PC (Wi-Fi, Ethernet, VPN, etc.).
- **Tshark** : outil qui ecoute les paquets en ligne de commande.
- **Python** : langage qui traite les donnees capturees.
- **Pure Data (Pd)** : logiciel de creation audio en temps reel.
- **OSC/UDP** : protocole de messages legers utilise pour piloter le son.

## 2) Fonctionnement global

1. `tshark` capture les paquets sur une interface reseau choisie.
2. Le script Python lit ces paquets et calcule des indicateurs (intensite, type d'evenement : `normal`, `flood`, `scan`, `syn_flood`, `spike`).
3. Le script ecrit en continu dans :
   - `normal_stream.txt` : trafic normal echantillonne ;
   - `suspicious_stream.txt` : uniquement les evenements suspects.
4. Pure Data recoit des messages OSC UDP (port `9000`) et genere le son.

Lecture :
- etape 1 = ecouter le reseau ;
- etape 2 = traduire ce qu'on ecoute en niveau d'alerte ;
- etape 3 = garder une trace dans des fichiers ;
- etape 4 = convertir la trace en son compréhensible.

## 3) Arborescence du projet

- `realtime_tshark_sonification.py` : analyseur principal.
- `normal_stream.txt` : sortie trafic normal.
- `suspicious_stream.txt` : sortie alertes.
- `tshark.exe` : binaire local (optionnel si tshark deja dans le `PATH`).
- `README.md` : documentation technique.
- `pd_ping_volume.pd` : Fichier Pure Data.

## 4) Prerequis logiciels

### Systeme
- Windows 10/11 (tests realises sous Windows).
- Droits administrateur recommandes pour la capture reseau.

### Outils a installer

1. **Python 3.10+**  
   Telechargement : [https://www.python.org/downloads/](https://www.python.org/downloads/)
   - cocher "Add Python to PATH" pendant l'installation.

2. **Wireshark (incluant Tshark)**  
   Telechargement : [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)  
   Pendant l'installation, verifier que `TShark` est bien installe.
   - installer Npcap si l'installateur le propose (necessaire pour capturer les paquets).

3. **Pure Data (Pd Vanilla)**  
   Telechargement : [https://puredata.info/downloads/pure-data](https://puredata.info/downloads/pure-data)
   - garder l'installation par defaut.

## 4.1) Check-list

Si tout est bien installe :
- `python --version` affiche un numero de version ;
- `tshark -v` affiche les informations tshark ;
- Pure Data s'ouvre et vous pouvez activer `DSP On`.

## 5) Installation et preparation (Windows)

### Etape A - Verifier Python

Dans `cmd` :

```bash
python --version
```

Résultat: `Python 3.x.x`.

### Etape B - Verifier Tshark

```bash
tshark -v
```

Ce que vous devez voir : la version de `TShark`.
Si vous voyez "commande introuvable", appliquez la methode locale (script + `tshark.exe` dans le meme dossier).

Si la commande ne fonctionne pas :
- soit ajouter le dossier d'installation Wireshark au `PATH` ;
- soit utiliser la methode qui a fonctionne pendant le projet : **placer le script Python dans le meme dossier que `tshark.exe`**, puis lancer depuis ce dossier.

### Etape C - (Optionnel) Environnement virtuel

```bash
python -m venv .venv
.venv\Scripts\activate
```

Le script utilise uniquement la bibliotheque standard Python (pas de dependances `pip` obligatoires pour l'analyse de base).
Donc, meme sans installation de librairies supplementaires, le projet peut fonctionner.

## 6) Execution (methode validee dans le projet)

Cette methode correspond exactement a ce qui a ete fait pour executer le script:

1. Ouvrir **Invite de commandes (cmd) en tant qu'administrateur**.
2. Se placer dans le dossier contenant `realtime_tshark_sonification.py` et `tshark.exe`.

3. Lister les interfaces :

```bash
tshark -D
```

4. Reperer l'interface a utiliser (exemple : `3`).
   - en general, l'interface active est celle qui correspond a votre Wi-Fi ou Ethernet ;
   - nous allons visualiser nos machines virtuelles sur l'interface Vmnet8
   - si vous hesitez, testez une interface puis regardez si les fichiers de sortie se remplissent.
5. Lancer l'analyse :

```bash
python .\realtime_tshark_sonification.py -i 3 --sensitivity medium --timestamp-format iso --debug
```

> Remplacer `3` par le numero reel de l'interface de votre machine.

6. Arret propre : `Ctrl + C`.

### 6.1) Pourquoi "cmd en admin" est souvent obligatoire

Capturer des paquets reseau est une operation sensible.
Sous Windows, sans droits admin, `tshark` peut :
- ne pas voir toutes les interfaces ;
- echouer a demarrer la capture ;
- retourner peu ou pas de donnees.

### 6.2) Ce qu'il se passe quand la commande tourne

- le terminal affiche des logs (mode `--debug`) ;
- `normal_stream.txt` se met a jour de temps en temps ;
- `suspicious_stream.txt` se met a jour seulement en cas d'anomalie ;
- si rien ne bouge, ouvrir un navigateur pour generer du trafic.

## 7) Parametres utiles du script

Commande de base :

```bash
python .\realtime_tshark_sonification.py -i <interface>
```

Options importantes :
- `--sensitivity low|medium|high` : sensibilite de detection.
- `--normal-output <fichier>` : chemin de sortie trafic normal.
- `--suspicious-output <fichier>` : chemin de sortie alertes.
- `--history-seconds <n>` : fenetre historique pour pics.
- `--timestamp-format iso|epoch|both` : format temporel.
- `--debug` : logs detaillees.

Interpretation simple :
- `low` = moins d'alertes (plus permissif) ;
- `medium` = bon compromis pour les demos ;
- `high` = plus d'alertes (plus sensible).

## 8) Format des sorties texte

Chaque ligne suit le format :

```text
timestamp ip_src ip_dst intensity type
```

Exemple :

```text
2026-04-20T13:45:18.127 192.168.1.10 8.8.8.8 62 normal
```

Comment lire cette ligne :
- `2026-04-20T13:45:18.127` : date/heure de l'evenement ;
- `192.168.1.10` : machine source ;
- `8.8.8.8` : destination ;
- `62` : intensite estimee (0 a 100) ;
- `normal` : type detecte.

Types possibles :
- `normal` : comportement courant ;
- `scan` : nombreuses tentatives sur des ports ;
- `flood` : volume de paquets tres eleve ;
- `syn_flood` : trop de paquets SYN ;
- `spike` : pic brutal de trafic.

## 9) Integration Pure Data (patch du binome)

Le patch `pd_ping_volume.pd` contient notamment :
- `netreceive -u -b 9000` : reception UDP/OSC sur le port `9000` ;
- `oscparse` + `list trim` : parsing des messages ;
- routage des messages `ping`, `volume`, `alert` ;
- generation sonore via `osc~`, `noise~`, `phasor~`, `line~`, puis sortie `dac~`.

### Lancement

1. Ouvrir Pure Data.
2. Charger `pd_ping_volume.pd`.
3. Activer l'audio (`Media -> DSP On`).
4. Verifier que le port UDP `9000` est libre.
5. Lancer la source de messages OSC (pont Python->OSC si utilise dans votre version projet).

Lecture debutant du patch :
- `route ping` declenche un "bip" (signal court) ;
- `route volume` agit sur un bruit filtre (niveau sonore variable) ;
- `route alert` declenche une alerte plus longue et plus marquante ;
- `dac~` envoie le resultat vers les haut-parleurs.

> Remarque : le script Python present ici ecrit dans des fichiers texte.  
> Si vous voulez piloter directement `pd_ping_volume.pd` en temps reel, il faut un envoi OSC vers `localhost:9000` avec des adresses `/ping`, `/volume`, `/alert`.

## 10) Protocole de demonstration en classe

Scenario recommande :

1. Demarrer Pure Data et activer le son.
2. Lancer le script Python avec `--debug`.
3. Generer du trafic normal (navigation web).
4. Observer le contenu de `normal_stream.txt`.
5. Simuler un trafic plus intense (test controle en environnement de TP uniquement).
6. Observer `suspicious_stream.txt` et la reaction sonore.
7. Faire expliquer aux etudiants le lien entre evenement reseau et parametre sonore.

Conseil enseignant :
- faire une premiere seance "decouverte" (comprendre les outils) ;
- puis une seance "analyse" (comparer trafic normal/suspect) ;
- terminer par une evaluation orale courte basee sur les observations.

## 11) Cadre d'usage pour une ecole

Pour un usage institutionnel, ajouter ces regles :
- Realiser les captures **uniquement** sur un reseau de TP autorise.
- Anonymiser les adresses IP dans les supports de rendu si necessaire.
- Informer les etudiants sur la finalite pedagogique de la capture.
- Ne pas utiliser l'outil pour une surveillance non autorisee.
- Integrer une charte d'utilisation et de protection des donnees.

## 12) Limites actuelles et ameliorations

Limites :
- detection heuristique (pas de modele ML) ;
- dependance aux droits de capture reseau ;
- le lien Python->OSC direct n'est pas inclus dans ce depot.

Ameliorations possibles :
- ajouter un module d'envoi OSC natif depuis Python ;
- ajouter une interface graphique de supervision ;
- exporter des statistiques (CSV/JSON) pour evaluation pedagogique ;
- ajouter des profils de sensibilite adaptes aux salles de TP.

## 13) Depannage rapide

- **`tshark` introuvable** : placer script + `tshark.exe` dans le meme dossier, ou corriger le `PATH`.
- **Aucune interface valide** : executer `tshark -D` en admin.
- **Fichiers de sortie vides** : verifier que du trafic circule sur l'interface choisie.
- **Pas de son Pure Data** : verifier `DSP On`, port `9000`, et routage OSC.
- **Message d'erreur Python** : verifier que vous etes bien dans le bon dossier avant de lancer la commande.
- **Doute sur l'interface** : changer la valeur de `-i` (ex: `1`, `2`, `3`) et relancer.

## 14) Auteurs

- Etudiant 1 : Theo MELLIEZ
- Etudiant 2 : Ange Michelle TCHEMTCHOUA
- Encadrement : Arthur PATE, Florian ALLEN

## 15) Licence (a completer)

Definir la licence de diffusion selon les consignes de l'etablissement (ex. MIT, CC BY-NC, usage pedagogique interne).
