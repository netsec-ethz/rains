import argparse
import random
import sys

from ipaddress import IPv4Address, IPv6Address
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
                        help="Prefix length for IPv4 addresses in a zone (0/8/16/24)")
    parser.add_argument("--ip6-pfxlen", type=int, default=56,
                        help="Prefix length for IPv6 addresses in a zone (bytewise)")
    parser.add_argument("--wordlist", type=str, default="words.txt", 
                        help="Wordlist to take entity names from")
    parser.add_argument("--out", type=str, default="-",
                        help="file to write to (default stdout)")

    
    return parser.parse_args()

# FIXME this doesn't work for some reason
def random_ipv4(pfxbytes=b""):
    addrbytes = bytearray(pfxbytes)
    for i in range(len(pfxbytes),4):
        addrbytes += bytearray((random.randrange(256),))
    return str(IPv4Address(addrbytes))

# FIXME this doesn't work for some reason
def random_ipv6(pfxbytes=b""):
    addrbytes = bytearray(pfxbytes)
    for i in range(len(pfxbytes),16):
        addrbytes += bytes((random.randrange(256),))
    return str(IPv6Address(addrbytes))

def generate_endhost(fp, name, v4_net, v6_net, args):
    v4_count = poisson(args.ip4_lambda)
    v6_count = poisson(args.ip6_lambda)
    if v4_count == 0 and v6_count == 0:
        v6_count = 1
    
    fp.write("    :A: %s [\n" % (name))
    for i in range(v6_count):
        fp.write("        :ip6: %s\n" % (str(random_ipv6(v6_net))))
    for i in range(v4_count):
        fp.write("        :ip4: 127.0.0.1\n" % (str(random_ipv4(v4_net))))
    fp.write("    ]\n")

def generate_delegation(fp, name, args):
    fp.write("    :A: %s [\n" % (name))
    fp.write("        ::deleg:: ed22519 keymaterial-goes-here\n")
    fp.write("    ]\n")

def generate_zone(fp, words, args):

    fp.write(":Z: %s %s [\n" % (args.context, args.zone))

    names_used = set()

    v4_net = random_ipv4().packed[:4-args.ip4_prefix/8]
    print("v4 net is "+repr(v4_net))
    v6_net = random_ipv6().packed[:16-args.ip6_prefix/8]
    print("v6 net is "+repr(v6_net))

    for i in range(args.name_count):
        typedie = random.randrange(args.endhost_weight + 
                                   args.delegation_weight)
        
        while True:
            worddie = random.randrange(len(words))
            if words[worddie] not in names_used:
                name = words[worddie]
                names_used.add(name)
                break
        
        if typedie < args.endhost_weight:
            generate_endhost(fp, name, args)
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
    
