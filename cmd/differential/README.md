# cmd package

*command-line client for differential cryptanalysis of Heys cipher*

```
NAME:
   differential - differential cryptanalysis of Heys cipher command line client

USAGE:
   cmd [global options] command [command options] [arguments...]

VERSION:
   0.0.1

DESCRIPTION:
   differential cryptanalysis ofa Heys cipher

AUTHOR:
   Tuzovska Mariia

COMMANDS:
   e                encrypt
   d                decrypt
   diff-search      search for defferentials
   diff-show        shows defferentials that has been found
   diff-attack      finds keys for differentials alpha and beta
   diff-attack-all  finds keys for all differentials alpha and beta in community/differentials.json
   diff-report      shows beautiful report about this fucking one
   key-found        shows keys that has been found for some aplpha and beta
   key-found-all    shows keys and their probability for all differentials that has been processed
   help, h          Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version

COPYRIGHT:
   2020, mariiatuzovska
```