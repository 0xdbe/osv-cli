# deps-dev-cli

CLI Node.js avec une commande `vulnerability` qui vérifie les vulnérabilités connues d'un package npm et de ses dépendances transitives via deps.dev + OSV.

## Prérequis

- Node.js 18+

## Installation locale

```bash
npm install
npm link
```

## Utilisation

```bash
vulnerability <nom-package>
vulnerability <nom-package> --version <version>
```

Si `--version` n'est pas fourni, la version par défaut du package est résolue via deps.dev.

La sortie inclut un tableau Markdown avec les colonnes:

- `nom du package`
- `version du package`
- `identifiant GHSA`
- `Score CVSS` (score numérique)
- `Niveau CVSS` (`None`, `Low`, `Medium`, `High`, `Critical`)

Exemples :

```bash
vulnerability lodash
vulnerability @types/node
vulnerability lodash -v 4.17.15
```

## Codes de sortie

- `0` : aucune vulnérabilité trouvée
- `1` : erreur d'usage ou erreur technique
- `2` : une ou plusieurs vulnérabilités trouvées
