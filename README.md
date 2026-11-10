# MAYO1 Lab

Projet pédagogique en Python organisé autour d'une implémentation existante du
schéma de signature MAYO1. Les calculs cryptographiques sont séparés de
l'orchestration et de l'affichage afin de faciliter leur test et une éventuelle
interface pédagogique ultérieure.

> **Important :** ce projet n'est ni une implémentation certifiée ni une
> affirmation de conformité à la spécification officielle MAYO Round 3. Les
> paramètres MAYO1 Round 3 sont configurés, mais les encodages doivent encore
> être comparés à des vecteurs officiels, notamment la valeur
> `F_TAIL = [8, 1, 1, 0]` et les conventions de compteur utilisées pour
> l'expansion AES. Ne l'utilisez pas pour protéger des données réelles.

## Architecture

```text
core/       Arithmétique GF(16), matrices, algèbre linéaire et formes quadratiques
crypto/     AES, aléatoire, hachage et encodage
keys/       Paramètres, génération et expansion des clés
scheme/     Émulsificateur, recherche de solution, signature et vérification
tests/      Tests pytest isolés du code de production
app.py      Orchestration de démonstration, sans dépendance d'interface
main.py     Point d'entrée en ligne de commande
```

`app.run_demo(message)` retourne un `DemoResult` contenant les clés compactes
et étendues, la signature et le résultat de vérification. Les fonctions
cryptographiques ne dépendent pas de Streamlit ni d'une autre interface.

## Installation

Python 3.10 ou plus récent est requis.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Sous Windows, activez l'environnement avec `.venv\Scripts\activate`.

## Exécution

Depuis la racine du dépôt :

```bash
python main.py
python main.py "message à signer"
```

La commande affiche les tailles des artefacts et le résultat de la vérification,
sans afficher les clés ni la signature.

## Tests

```bash
python -m pytest -v
```

Les tests vérifient les opérations de corps fini et de matrices, la génération
et l'expansion des clés, puis les chemins de signature et de vérification.

## Interface Streamlit

Installez les dépendances du projet, qui incluent Streamlit :

```bash
python -m pip install -r requirements.txt
```

Depuis la racine du dépôt, lancez le tableau de bord avec :

```bash
streamlit run streamlit_app.py
```

Les vues Génération des clés et Signature appellent le moteur local uniquement
sur action explicite et conservent leurs résultats dans l’état de la session
Streamlit sans afficher de clé secrète. La signature affiche sa trace
pédagogique et garde son hexadécimal masqué par défaut. La vue détaillée de
vérification reste en développement. La section Analyse affiche les tailles
dérivées des paramètres locaux; son chronométrage n’apparaît qu’après une
exécution réelle demandée explicitement.

## Trace pédagogique de Sign

`sign(esk, message)` conserve son comportement historique et renvoie seulement
les octets de signature. Pour demander la trace, appeler :

```python
signature, trace = sign(esk, message, return_trace=True)
```

### Structure des objets

La définition de `TraceStep` dans `scheme/trace.py` est :

```python
@dataclass(frozen=True)
class TraceStep:
    number: int
    name: str
    description: str
    data: TraceData = field(default_factory=dict)
    dimensions: Dimensions = field(default_factory=dict)
    status: str = "completed"
    attempt: int | None = None
    operation: Literal["sign", "verify"] = "sign"

    @property
    def scope(self) -> str: ...
```

Les alias de types sont :

```python
TraceData = dict[
    str,
    str | int | bool | list[int] | list[list[int]] | None,
]
Dimensions = dict[str, tuple[int, ...]]
```

`SignTrace` est une dataclass mutable contenant `steps: list[TraceStep]`.
Sa méthode `add_step(name, description, *, data=None, dimensions=None,
status="completed", attempt=None)` ajoute une étape et lui attribue le prochain
numéro, commençant à 1. Les numéros restent globaux et dans l'ordre
d'exécution. `attempt` vaut `None` pour les étapes communes à la signature ou
le numéro (à partir de 1) pour les étapes d'une tentative; la propriété
calculée `scope` vaut `"signature"` ou `"attempt"`. `operation` vaut
`"sign"` par défaut, ce qui conserve la création historique des étapes Sign.
Les étapes Verify sont marquées `"verify"` et ont la portée `"verification"`.
`TraceStep` est immuable, mais ses dictionnaires `data` et `dimensions` restent
des objets Python mutables. `SignTraceError`, utilisée pour une signature qui
échoue lorsque le traçage est activé, est une sous-classe de `RuntimeError` qui
conserve la trace partielle dans `error.trace`.
`VerifyTrace` fournit la même interface `steps` / `add_step` / `to_dict` pour
la vérification; ses étapes sont identifiées par `operation="verify"` et
`scope="verification"`.

### Exemple réel exécuté

Une exécution a généré une nouvelle paire de clés, signé le message
`"Bonjour MAYO1"` avec `return_trace=True`, puis vérifié la signature. Résultat
observé : **321 octets**, vérification **`0`** (valide), et **10 étapes**.
Les clés n’ont pas été affichées. Le sel est une composante publique de la
signature, mais son hexadécimal est masqué dans ce rapport par prudence. Les
aléas et coefficients secrets ou dérivés de secrets ne sont pas inclus dans la
trace.

La trace complète expurgée de cette exécution est :

Cet exemple historique présente les champs propres à Sign; la sérialisation
actuelle ajoute aussi `"operation": "sign"` à chaque étape.

```json
{
  "steps": [
    {
      "number": 1,
      "name": "secret_key_prepared",
      "attempt": null,
      "scope": "signature",
      "description": "La clé étendue a été analysée en mémoire; ses éléments secrets ne sont pas copiés dans la trace.",
      "data": {
        "expanded_key_bytes": 69856,
        "polynomial_count": 64,
        "linking_matrix_count": 64
      },
      "dimensions": {
        "O": [58, 8],
        "P1": [64, 58, 58],
        "L": [64, 58, 8]
      },
      "status": "completed"
    },
    {
      "number": 2,
      "name": "message_digest",
      "attempt": null,
      "scope": "signature",
      "description": "SHAKE256 calcule le digest du message.",
      "data": {
        "digest_bytes": 32,
        "digest_preview_hex": "dbc08571cce50ff9"
      },
      "dimensions": {},
      "status": "completed"
    },
    {
      "number": 3,
      "name": "salt_generated",
      "attempt": null,
      "scope": "signature",
      "description": "Le sel est dérivé du digest, d'un aléa éphémère et de la graine secrète; seuls le sel public et la taille de l'aléa sont tracés.",
      "data": {
        "salt_bytes": 24,
        "salt_hex": "[masqué]",
        "random_input_bytes": 24
      },
      "dimensions": {},
      "status": "completed"
    },
    {
      "number": 4,
      "name": "target_and_lambda_derived",
      "attempt": null,
      "scope": "signature",
      "description": "Le vecteur cible t et la matrice Lambda sont dérivés du digest et du sel.",
      "data": {
        "t_preview": [5, 3, 12, 14, 3, 1, 10, 12],
        "lambda_preview": [[15, 10, 5, 0], [12, 2, 13, 3]]
      },
      "dimensions": {
        "t": [64],
        "Lambda": [64, 66]
      },
      "status": "completed"
    },
    {
      "number": 5,
      "name": "emulsifier_loaded",
      "attempt": null,
      "scope": "signature",
      "description": "La table des matrices E est récupérée pour combiner les blocs du système.",
      "data": {
        "block_count": 9
      },
      "dimensions": {
        "E_table": [9, 9],
        "E_entry": [64, 64]
      },
      "status": "completed"
    },
    {
      "number": 6,
      "name": "attempt_values_generated",
      "attempt": 1,
      "scope": "attempt",
      "description": "SHAKE256 dérive les blocs vinegar et le vecteur aléatoire de la tentative; leurs coefficients ne sont pas enregistrés.",
      "data": {
        "attempt": 1,
        "counter": 0,
        "random_output_bytes": 297,
        "vinegar_block_count": 9,
        "random_vector_elements": 72
      },
      "dimensions": {
        "vinegar_blocks": [9, 58],
        "r": [72]
      },
      "status": "completed"
    },
    {
      "number": 7,
      "name": "intermediate_matrices_built",
      "attempt": 1,
      "scope": "attempt",
      "description": "Les matrices intermédiaires liées aux blocs vinegar et les produits W sont construits; leurs coefficients sensibles sont omis.",
      "data": {
        "M_matrix_count": 9,
        "W_vector_count": 576,
        "coefficients_recorded": false
      },
      "dimensions": {
        "M_matrices": [9, 64, 8],
        "W": [9, 64, 58]
      },
      "status": "completed"
    },
    {
      "number": 8,
      "name": "linear_system_built",
      "attempt": 1,
      "scope": "attempt",
      "description": "Les contributions des blocs sont accumulées pour former A x = y; les coefficients ne sont pas exposés.",
      "data": {
        "matrix_coefficients": 4608,
        "target_elements": 64,
        "coefficients_recorded": false
      },
      "dimensions": {
        "A": [64, 72],
        "y": [64],
        "r": [72]
      },
      "status": "completed"
    },
    {
      "number": 9,
      "name": "sample_solution",
      "attempt": 1,
      "scope": "attempt",
      "description": "SampleSolution cherche une solution en utilisant r pour les variables libres.",
      "data": {
        "attempt": 1,
        "solution_found": true,
        "reason": "solution_found"
      },
      "dimensions": {
        "solution": [72]
      },
      "status": "solved"
    },
    {
      "number": 10,
      "name": "signature_encoded",
      "attempt": null,
      "scope": "signature",
      "description": "Les blocs de signature sont assemblés, encodés puis concaténés au sel.",
      "data": {
        "vector_elements": 594,
        "encoded_vector_bytes": 297,
        "salt_bytes": 24,
        "signature_bytes": 321
      },
      "dimensions": {
        "signature_blocks": [9, 66],
        "signature_vector": [594]
      },
      "status": "completed"
    }
  ]
}
```

Les valeurs de digest, de `t` et de `Lambda` ci-dessus sont les aperçus réels
de cette exécution. Le sel est explicitement expurgé ici. Les dimensions et les
tailles sont des métadonnées; aucune valeur de matrice secrète, graine, clé ou
vecteur aléatoire interne n’est montrée.

### Récupérer et parcourir la trace depuis un autre module

Par exemple, une future interface peut importer `sign`, récupérer les étapes
et afficher leurs champs sans intégrer de code d’interface dans les modules
cryptographiques :


```python
from scheme.sign import sign

signature, trace = sign(expanded_secret_key, "Bonjour MAYO1", return_trace=True)

for step in trace.steps:
    print(step.number, step.name, step.status)
    print(step.description)
    print("Données :", step.data)
    print("Dimensions :", step.dimensions)
```

Ne pas afficher ou enregistrer `expanded_secret_key`, la clé compacte, ni les
variables locales de la fonction de signature.

### Sérialisation JSON

`SignTrace.to_dict()` et `VerifyTrace.to_dict()` convertissent les traces en
dictionnaires, listes et valeurs scalaires compatibles JSON. Les dimensions,
stockées sous forme de tuples dans les objets Python, sont converties en listes.
Chaque événement sérialisé contient également `operation` et `scope` :

```python
import json

json_text = json.dumps(trace.to_dict(), ensure_ascii=False, indent=2)
```

Le dictionnaire conserve le champ `attempt` et le `scope` calculé pour permettre
de regrouper les événements par tentative sans perdre leur numéro ni leur ordre
global. Pour Verify, `operation` vaut `"verify"` et `scope` vaut
`"verification"`. La sérialisation n'ajoute pas les valeurs cryptographiques
omises de la trace. Il faut néanmoins maintenir le filtrage des données
sensibles avant toute persistance ou transmission.

## Trace pédagogique de Verify

L'appel historique `verify(epk, message, signature)` renvoie toujours un entier :
`0` si la signature est acceptée, `-1` sinon. Pour obtenir en plus la trace :

```python
result, trace = verify(
    expanded_public_key,
    message,
    signature,
    return_trace=True,
)
```

Le résultat accompagné de la trace est disponible aussi pour les rejets
anticipés reconnus. Les événements gardent leur numéro de séquence global;
`operation="verify"` et `scope="verification"` les distinguent de ceux de Sign.
Le chemin valide comprend, dans l'ordre, `message_normalized`,
`public_key_parsed`, `signature_length_checked`, `signature_split`,
`signature_vector_decoded`, `signature_blocks_partitioned`,
`message_digest_computed`, `target_and_lambda_derived`, `emulsifier_loaded`,
`quadratic_form_evaluated`, `lambda_contributions_added` et
`verification_compared`. Un type d'argument invalide produit
`input_rejected`; un rejet anticipé arrête la trace à l'étape concernée.
Les événements de rejet portent un code stable dans `data["error_code"]` :
`public_key_format_error`, `signature_length_error`,
`signature_decode_error`, `derivation_error` ou `verification_mismatch`.
Les rejets des types d'arguments ou d'un texte non encodable en UTF-8 utilisent
respectivement `input_type_error` et `message_encoding_error`.

La trace indique les dimensions et les tailles, mais n'enregistre pas le
message, la clé publique, les octets de signature, le sel, les éléments de
signature, les coefficients de matrices, ni les valeurs complètes de `t` ou de
`Lambda`. Elle ne copie pas le texte des exceptions. Le digest et les aperçus
numériques sont omis pour éviter de faciliter la confirmation de messages
prévisibles dans une trace partagée.

## Paramètres et encodages conservés

Les paramètres MAYO1 Round 3 configurés sont `Q=16`, `N=66`, `M=64`,
`O_DIM=8`, `K=9` et `V=58`, avec des graines secrète/publique de 24/16 octets,
un digest de 32 octets et un sel de 24 octets. Les tailles dérivées sont :
clé publique compacte **1168 octets**, clé secrète compacte **24 octets**, clé
publique étendue **70752 octets**, clé secrète étendue **69856 octets** et
signature **321 octets**. Ces valeurs ne constituent pas une attestation de
conformité normative.
