# deps-dev-cli

## Prérequis

- Node.js 18+

## Installation locale

```bash
npm install
```

## Utilisation

```bash
node src/cli.js <nom-package> -v <version> -e <ecosysteme>
```


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
