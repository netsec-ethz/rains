import argparse
import sys
import os.path

import nacl.signing
import nacl.encoding

from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

from random import randrange
from numpy.random import poisson

def parse_args():

    parser = argparse.ArgumentParser(description="Generate a RAINS zonefile for testing")

    parser.add_argument("--zone", type=str, default=".",
                        help="Name of zone to create")
    parser.add_argument("--context", type=str, default=".",
                        help="Context to create zone in")                
    parser.add_argument("--name-count", type=int, default=1, 
                        help="Number of named entities to create")
    parser.add_argument("--endhost-weight", type=int, default=1,
                        help="Relative weight of endhosts in zone")
    parser.add_argument("--delegation-weight", type=int, default=0,
                        help="Relative weight of delegations in zone")
    parser.add_argument("--ip4-lambda", type=float, default=1.0,
                        help="Parameter to Poisson distribution for v4 addresses per host")
    parser.add_argument("--ip6-lambda", type=float, default=1.0,
                        help="Parameter to Poisson distribution for v4 addresses per host")
    parser.add_argument("--ip4-pfxlen", type=int, default=16,
                        help="Prefix length for IPv4 addresses in a zone")
    parser.add_argument("--ip6-pfxlen", type=int, default=56,
                        help="Prefix length for IPv6 addresses in a zone")
    parser.add_argument("--wordlist", type=str, default="words.txt", 
                        help="Wordlist to take entity names from")
    parser.add_argument("--out", type=str, default="-",
                        help="file to write to (default stdout)")
    parser.add_argument("--keydir", type=str,
                        help="if present, write binary secret keys to keydir as zone.sk")

    
    return parser.parse_args()

def random_ipv4(net=IPv4Network("0.0.0.0/0")):
    return net[randrange(2 ** (32 - net.prefixlen))]


def random_ipv6(net=IPv6Network("2000::/3")):
    return net[randrange(2 ** (128 - net.prefixlen))]

def generate_endhost(fp, name, v4_net, v6_net, args):
    v4_count = poisson(args.ip4_lambda)
    v6_count = poisson(args.ip6_lambda)
    if v4_count == 0 and v6_count == 0:
        v6_count = 1
    
    fp.write("    :A: %s [\n" % (name))
    for i in range(v6_count):
        fp.write("        :ip6: %s\n" % (str(random_ipv6(v6_net))))
    for i in range(v4_count):
        fp.write("        :ip4: %s\n" % (str(random_ipv4(v4_net))))
    fp.write("    ]\n")

def generate_delegation(fp, name, args):
    # make a secret key
    sk = nacl.signing.SigningKey.generate()

    # dump it to disk
    if args.keydir:
        zone = args.zone.strip(".")
        if len(zone) > 0:
            skname = ".".join([name, zone]) + ".sk"
        else:
            skname = name + ".sk"
        with open(os.path.join(args.keydir, skname), mode="wb") as keyfile:
            keyfile.write(bytes(sk))
    
    # and output the associated public key
    fp.write("    :A: %s [\n" % (name))
    fp.write("        :deleg: ed25519 %s\n" % (bytes(sk.verify_key).hex()))
    fp.write("    ]\n")

def generate_zone(fp, words, args):

    fp.write(":Z: %s %s [\n" % (args.context, args.zone))

    names_used = set()

    v4_net = IPv4Network(str(random_ipv4())+"/"+str(args.ip4_pfxlen), strict=False)
    v6_net = IPv6Network(str(random_ipv6())+"/"+str(args.ip6_pfxlen), strict=False)

    for i in range(args.name_count):
        typedie = randrange(args.endhost_weight + 
                            args.delegation_weight)
        
        while True:
            worddie = randrange(len(words))
            if words[worddie] not in names_used:
                name = words[worddie]
                names_used.add(name)
                break
        
        if typedie < args.endhost_weight:
            generate_endhost(fp, name, v4_net, v6_net, args)
        else:
            generate_delegation(fp, name, args)

    fp.write("]\n")

if __name__ == "__main__":

    args = parse_args()

    with open(args.wordlist) as wordlist:
        words = [word.strip() for word in wordlist]
    
    if args.out == "-":
        generate_zone(sys.stdout, words, args)
    else:
        with open(args.out, mode="w") as f:
            generate_zone(f, words, args)
    
