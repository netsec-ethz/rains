#!/usr/bin/env python3

# RAINS Zonefile Compiler
# Turns RAINS zonefiles into CBOR, and vice versa
# Prototype/testing; to be incorporated into RAINSD

# NOTE: this implements zonefile declarations in zone-context order, the
# design document (which is normative) uses context-zone order. Change this
# code.

import re
import cbor
from ipaddress import ip_address
from collections import namedtuple

K_SIGNATURES     = 0
K_CAPABILITIES   = 1 
K_TOKEN          = 2 
K_SUBJECT_NAME   = 3 
K_SUBJECT_ZONE   = 4 
K_QUERY_NAME     = 5 
K_CONTEXT        = 6 
K_OBJECTS        = 7 
K_QUERY_CONTEXTS = 8
K_QUERY_TYPES    = 9
K_QUERY_OPTS     = 10
K_SHARD_RANGE    = 11
K_SUBJECT_ADDR   = 12 # FIXME document in draft
K_NOTE_TYPE      = 21
K_NOTE_DATA      = 22
K_CONTENT        = 23 

OBJ_NAME         = 1 
OBJ_IP6          = 2 
OBJ_IP4          = 3 
OBJ_REDIRECTION  = 4 
OBJ_DELEGATION   = 5 
OBJ_NAMESET      = 6 
OBJ_CERT_INFO    = 7 
OBJ_SERVICE_INFO = 8 
OBJ_REGISTRAR    = 9 
OBJ_REGISTRANT   = 10
OBJ_INFRAKEY     = 11
OBJ_ANYADDR      = 23 # FIXME document in draft

SEC_ASSERTION     = 1 
SEC_SHARD         = 2 
SEC_ZONE          = 3 
SEC_QUERY         = 4 
SEC_NOTIFICATION  = 23

ALGORITHMS = { "ECDSA256" : 2,
               "ECDSA384" : 3}

Token = namedtuple("Token", ["t", "v", "p"])

def debug_scanner_open(s,t):
    print(repr(s.__dict__))
    return Token (t, None)

scanner = re.Scanner([
    (r"\(",             lambda s,t:(Token(t,                  None, s.match.span()))),
    (r"\)",             lambda s,t:(Token(t,                  None, s.match.span()))),
    (r"\[",             lambda s,t:(Token(t,                  None, s.match.span()))),
    (r"\]",             lambda s,t:(Token(t,                  None, s.match.span()))),
    (r",",              lambda s,t:(Token(t,                  None, s.match.span()))),
    (r":Z:\s+",         lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":S:\s+",         lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":A:\s+",         lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":sig:\s+",       lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":ip4:\s+",       lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":ip6:\s+",       lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":name:\s+",      lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":deleg:\s+",     lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":redir:\s+",     lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":cert:\s+",      lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":infra:\s+",     lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":nameset:\s+",   lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":regr:\s+",      lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":regt:\s+",      lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r":srv:\s+",       lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
    (r"\d+\.\d+\.\d+\.\d+",
                        lambda s,t:(Token("VAL_IP4", ip_address(t), s.match.span()))),
    (r"::",
                        lambda s,t:(Token("VAL_IP6", ip_address(t), s.match.span()))),
    (r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
                        lambda s,t:(Token("VAL_IP6", ip_address(t), s.match.span()))),
    (r"([0-9a-fA-F]{1,4}:){0,7}:([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}",
                        lambda s,t:(Token("VAL_IP6", ip_address(t), s.match.span()))),
    (r"\d+-\d+-\d+T\d+:\d+:\d+",
                        lambda s,t:(Token("VAL_8601",    
                            (datetime.strptime(t,"%Y-%m-%dT%H:%M:%S") - 
                             datetime(1970,0,1)).total_seconds(), s.match.span()))),
    (r"[1-9][0-9]*",
                        lambda s,t:(Token("VAL_INT",             t, s.match.span()))),
    (r"[0-9a-fA-F]{2,128}",
                        lambda s,t:(Token("VAL_HEX",             t, s.match.span()))),
    (r":[a-zA-Z][a-zA-Z0-9_]*:\s+",
                        lambda s,t:(Token("TOK_RESERVED",     None, s.match.span()))),
    (r"\S+",            lambda s,t:(Token("VAL_STRING",          t, s.match.span()))),
    (r"\s+",            lambda s,t:None),
    (r"#\.*\n",         lambda s,t:None)
])


def is_string(tok):
    return (tok.t == "VAL_STRING" or
            tok.t == "VAL_HEX" or
            tok_t == "VAL_INT")

def is_object_sym(tok):
    return (tok.t == ":Z:" or
           tok.t == ":S:" or
           tok.t == ":A:" or
           tok.t == ":sig:" or
           tok.t == ":ip4:" or
           tok.t == ":ip6:" or
           tok.t == ":name:" or
           tok.t == ":deleg:" or
           tok.t == ":redir:" or
           tok.t == ":cert:" or
           tok.t == ":infra:" or
           tok.t == ":nameset:" or
           tok.t == ":regr:" or
           tok.t == ":regt:" or
           tok.t == ":srv:")


def consume_symbol(ts, sym):
    if ts[0].t != sym:
        raise ValueError("expected "+str(sym)+", got "+str(ts.v), "at "+str(ts[0].p[0]))
    return ts[1:]

def section(ts):
    if ts[0].t == ":Z:":
        if not is_string(ts[1]) or not is_string(ts[2]) :
            raise ValueError("missing zone and/or context in :Z: at"+str(ts[0].p[0]))
        z, ts = zone(ts[3:], ts[1].v, ts[2].v)
        return [ SEC_ZONE, z ]
    elif ts[0].t == ":S:":
        if not is_string(ts[1]) or not is_string(ts[2]) :
            raise ValueError("missing zone and/or context in bare :S: at"+str(ts[0].p[0]))
        s, ts = shard(ts[3:], ts[1].v, ts[2].v, True)
        return [ SEC_SHARD, s], ts
    elif ts[0].t == ":A:":
        if not is_string(ts[1]) or not is_string(ts[2]) :
            raise ValueError("missing zone and/or context in bare :A: at"+str(ts[0].p[0]))
        a, ts = assertion(ts[3:], ts[1].v, ts[2].v, True)
        return [ SEC_ASSERTION, a ]
    else:
        raise ValueError("expected :Z:, :S:, or :A: at "+str(ts[0].p[0]))

def zone(ts, zone_name, context_name):
    out = { K_SUBJECT_ZONE:    zone_name,
            K_CONTEXT:      context_name,
            K_CONTENT:      [] }

    ts = consume_symbol(ts, "[")

    # eat content
    while ts[0].t != "]":
        if ts[0].t == ":S:":
            s, ts = shard(ts[1:], zone_name, context_name, False)
            out[K_CONTENT].append(s)
        elif ts[0].t == ":A:":
            a, ts = assertion(ts[1:], zone_name, context_name, False)
            out[K_CONTENT].append(a)
        else:
            raise ValueError("expected :S:, :A:, or ] at "+str(ts[0].p[0]))
    ts = consume_symbol(ts, "]")

    # and signatures, if present
    out[K_SIGNATURES], ts = signatures(ts)

    return out, ts

def shard(ts, zone_name, context_name, is_section):
    out = { K_SUBJECT_ZONE:    zone_name,
            K_CONTEXT:      context_name,
            K_CONTENT:      [],
            K_SHARD_RANGE:  [] }

    # check for range
    if ts[0].t == "(":
        ts = ts[1:]
        if is_string(ts[0]):
            out[K_SHARD_RANGE].append(ts[0].v)
            ts = consume_symbol(ts[1:],",")
        elif ts[0].t == ",":
            out[K_SHARD_RANGE].append(None)
            ts = ts[1:]
        else:
            raise ValueError("expected shard range begin or , at "+str(ts[0].p[0]))

        if is_string(ts[0]):
            out[K_SHARD_RANGE].append(ts[0].v)
            ts = ts[1:]
        elif (ts[0].t == ")"):
            out[K_SHARD_RANGE].append(None)
        else:
            raise ValueError("expected shard range end or ) at "+str(ts[0].p[0]))
        ts = consume_symbol(ts, ")")

    ts = consume_symbol(ts, "[")

    # eat content
    while ts[0].t != "]":
        if ts[0].t == ":A:":
            a, ts = assertion(ts[1:], zone_name, context_name, False)
            out[K_CONTENT].append(a)
        else:
            raise ValueError("expected :A: or ] at "+str(ts[0].p[0]))
    ts = consume_symbol(ts, "]")    

    # and signatures, if present
    out[K_SIGNATURES], ts = signatures(ts)

    if not is_section:
        del(out[K_SUBJECT_ZONE])
        del(out[K_CONTEXT])

    if (len(out[K_SHARD_RANGE]) < 2 or 
        (out[K_SHARD_RANGE][0] is None and 
            out[K_SHARD_RANGE][1] is None)):
        del(out[K_SHARD_RANGE])

    return out, ts

def assertion(ts, zone_name, context_name, is_section):
    out = { K_SUBJECT_ZONE:    zone_name,
            K_CONTEXT:      context_name,
            K_OBJECTS:      [] }

    if is_string(ts[0]):
        out[K_SUBJECT_NAME] = ts[0].v
        ts = ts[1:]
    else:
        raise ValueError("Expected assertion subject name at "+str(ts[0].p[0]))

    ts = consume_symbol(ts, "[")

    # eat object content
    while ts[0].t != "]":
        o, ts = objekt(ts)
        out[K_OBJECTS].append(o)
    ts = consume_symbol(ts, "]") 

    # and signatures, if present
    out[K_SIGNATURES], ts = signatures(ts)

    if not is_section:
        del(out[K_SUBJECT_ZONE])
        del(out[K_CONTEXT])

    return out, ts

def objekt(ts):
    if ts[0].t == ":ip4:":
        if ts[1].t != "VAL_IP4":
            raise ValueError("expected IPv4 address at "+str(ts[0].p[0]))
        return [ OBJ_IP4, ts[1].v.packed ], ts[2:]

    elif ts[0].t == ":ip6:":
        if ts[1].t != "VAL_IP6":
            raise ValueError("expected IPv6 address at "+str(ts[0].p[0]))
        return [ OBJ_IP6, ts[1].v.packed ], ts[2:]

    elif ts[0].t == ":name:":
        if ts[1].t != "VAL_STRING":
            raise ValueError("expected name at "+str(ts[0].p[0]))
        return [ OBJ_NAME, ts[1].v ], ts[2:]

    elif ts[0].t == ":redir:":
        if ts[1].t != "VAL_STRING":
            raise ValueError("expected redirection name at "+str(ts[0].p[0]))
        return [ OBJ_REDIRECTION, ts[1].v ], ts[2:]

    elif ts[0].t == ":srv:":
        if (ts[1].t != "VAL_STRING" or
            ts[2].t != "VAL_INT" or
            ts[3].t != "VAL_INT"):
            raise ValueError("expected service info at "+str(ts[0].p[0]))
        return [ OBJ_SERVICE_INFO, ts[1].v, int(ts[2].v), int(ts[3].v) ], ts[4:]

    elif ts[0].t == ":deleg:":
        if is_string(ts[1].t):
            alg = ALGORITHMS[ts[1].v]
        else:
            raise ValueError("expected key algorithm at "+str(ts[0].p[0]))
        ts = ts[2:]
        hexkey = ""
        while ts[0].t == "VAL_HEX":
            hexkey += ts[0].v
            ts = ts[1:]
        return [ OBJ_DELEGATION, alg, bytes.fromhex(hexkey) ], ts

    elif ts[0].t == ":infra:":
        if is_string(ts[1].t):
            alg = ALGORITHMS[ts[1].v]
        else:
            raise ValueError("expected key algorithm at "+str(ts[0].p[0]))
        ts = ts[2:]
        hexkey = ""
        while ts[0].t == "VAL_HEX":
            hexkey += ts[0].v
            ts = ts[1:]
        return [ OBJ_INFRAKEY, alg, bytes.fromhex(hexkey) ], ts

    elif ts[0].t == ":regr:":
        ts = ts[1:]
        regr_strings = []
        while not is_object_sym(ts[0]) and ts[0].t != "]":
            regr_strings.append(ts[0].v)
            ts = ts[1:]
        return [ OBJ_REGISTRAR, " ".join(regr_strings) ], ts

    elif ts[0].t == ":regt:":
        ts = ts[1:]
        regr_strings = []
        while not is_object_sym(ts[0]) and ts[0].t != "]":
            regr_strings.append(ts[0].v)
            ts = ts[1:]
        return [ OBJ_REGISTRANT, " ".join(regr_strings) ], ts

    elif ts[0].t == ":cert:":
        ts = ts[1:]
        while not is_object_sym(ts[0]) and ts[0].t != "]":
            ts = ts[1:]
            return [ OBJ_CERT_INFO ], ts

    elif ts[0].t == ":nameset:":
        ts = ts[1:]
        while not is_object_sym(ts[0]) and ts[0].t != "]":
            ts = ts[1:]
            return [ OBJ_NAMESET ], ts

    else:
        raise ValueError("expected object at at "+str(ts[0].p[0]))

def signatures(ts):
    out = []

    # check for signature
    if len(ts) and ts[0].t == "(":
        ts = ts[1:]
        while ts[0].t != ")":
            s, ts = signature(ts)
            out.append(s)
        ts = consume_symbol(")")

    return out, ts

def signature(ts):
    ts = consume_symbol(":sig:", ts)
    if is_string(ts[0].t):
        alg = ALGORITHMS[ts[0].v]
    else:
        raise ValueError("expected signature algorithm at "+str(ts[0].p[0]))

    if ts[1].t == "VAL_8601":
        st = ts[1].v
    else:
        raise ValueError("expected start of validity at "+str(ts[0].p[0]))

    if ts[2].t == "VAL_8601":
        st = ts[2].v
    else:
        raise ValueError("expected end of validity at "+str(ts[0].p[0]))

    ts = ts[3:]
    hexsig = ""
    while ts[0].t == "VAL_HEX":
        hexsig += ts[0].v
        ts = ts[1:]
    
    return [ alg, st, et, bytes.fromhex(hexkey) ], ts


test_zone_1 = """
:Z: example.com . [
    :S: [
        :A: _smtp._tcp [ :srv: mx 25 10 ]
        :A: foobaz [
            :ip4: 192.0.2.33
            :ip6: 2001:db8:cffe:7ea::33
        ]
        :A: quuxnorg [
            :ip4: 192.0.3.33
            :ip6: 2001:db8:cffe:7eb::33
        ]
    ]
]
"""