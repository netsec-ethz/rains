keyManager(1) -- A RAINS key manager
=================================

## SYNOPSIS

`keyManager` [command] [path] [options]

## DESCRIPTION

keyManager is a tool for managing public private key pairs for the RAINS infrastructure from the
command line. It offers key generation for all algorithms supported by RAINS and stores the keys pem
encoded. The private key is encrypted using aes before being pem encoded. The aes key is generated
from a user provided password. Given the name of the key and the correct password, the keyManager
decrypts the private key and prints it pem encoded.

## OPTIONS

* path:
    Path where the keys are or will be stored. The current location is the default path.

* `-n`, `--name`:
    The prefix of the file name where the key is loaded from or will be stored to.

* `-a`, `--algo`:
    Defines the algorithm which is used in key generation. The default is ed25519. Supported
    algorithms are: ed25519

* `--phase`:
    Defines the key phase for which a key is generated. The default is 0

* `-d`, `--description`:
    Description allows to store an arbitrary string value with the key. It can e.g. be used to store
    the information in which zone and context the key pair is used. The default is the empty string.

* `--pwd`:
    Pwd states the password to encrypt or decrypt a private key. The default is the empty string.

## COMMANDS
* `load`, `l`:
    Prints all public keys stored at the provided path.
* `generate`, `gen`, `g`:
    Generate first creates a new public-private key pair according to the provided algorithm. It
    then encrypts the private key with the provided password. Lastly, it pem encodes the private and
    public key separately and stores them at the provided path. The file prefix corresponds to the
    provided name followed by _sec.pem or _pub.pem (for private or public key).
* `decrypt`, `d`:
    Decrypt loads the pem encoded private key at path corresponding to the provided name. It then
    encrypts the private key with the user provided password and prints to decrypted key pem encoded
    to the stdout.

## EXAMPLES

TODO
