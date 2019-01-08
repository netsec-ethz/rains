keyManager(1) -- A RAINS key manager
=================================

## SYNOPSIS

`keyManager` [-p|--path <path>] <command> 

## DESCRIPTION

TODO

## OPTIONS

* `-n`, `--name`:
    The context within which to query for assertions. For example to query within the global context
    `.` would be used as the context, or to query within a specific context such as `inf.ethz.ch`,
    that context can be specified with this options.

* `-a`, `--algo`:
    TODO
* `--phase`:
    TODO
* `-d`, `--description`:
    TODO
* `-pwd`:
    TODO
var keyPath = flag.StringP("path", "p", "", "Path where the keys are or will be stored.")
var keyName = flag.StringP("name", "n", "", "Name determines the prefix of the key pair's file name")
var algo = flag.StringP("algo", "a", "ed25519", "Algorithm used to generate key")
var phase = flag.Int("phase", 0, "Key phase of the generated key")
var description = flag.StringP("description", "d", "", "description added when a new key pair is generated")
var pwd = flag.String("pwd", "", "password to used to encrypt a newly generated key pair")

## COMMANDS
* `load`, `l`:
    TODO
* `generate`, `gen`, `g`:
    TODO
* `decrypt`, `d`:
    TODO

## EXAMPLES

TODO
