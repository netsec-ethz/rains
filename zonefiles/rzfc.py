#!/usr/bin/env python3

# RAINS Zonefile Compiler
# Turns RAINS zonefiles into CBOR, and vice versa
# Prototype/testing. Under current development.

# NOTE: this implements zonefile declarations in zone-context order, the
# design document (which is normative) uses context-zone order. Change this
# code. NOTE NOTE: in progress.

# NOTE: EXTRAKEY not yet supported. Change this code.

# NOTE: Keyspace identifiers not yet supported. Change this code.

# NOTE: need to support reverse assertions as in draft

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
OBJ_EXTRAKEY     = 12 # FIXME add support for extrakey / keyspaces
OBJ_ANYADDR      = 23 # FIXME document in draft

SEC_ASSERTION     = 1
SEC_SHARD         = 2
SEC_ZONE          = 3
SEC_QUERY         = 4
SEC_NOTIFICATION  = 23

ALGORITHMS = { "ed25519"  : 1,
               "ed448"    : 2,
               "ECDSA256" : 3,
               "ECDSA384" : 4}

KEYSPACES = { "rains"     : 0 }

INDENT_LEN = 4 # let the religious wars begin

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
    (r":extra:\s+",     lambda s,t:(Token(t.rstrip(),         None, s.match.span()))),
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
    (r"\s+",            lambda s,t:None), # ignore whitespace
    (r"#\.*\n",         lambda s,t:None)  # ignore comments
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
           tok.t == ":extra:" or
           tok.t == ":nameset:" or
           tok.t == ":regr:" or
           tok.t == ":regt:" or
           tok.t == ":srv:")


def _consume_symbol(ts, sym):
    if ts[0].t != sym:
        raise ValueError("expected "+str(sym)+", got "+str(ts.v), "at "+str(ts[0].p[0]))
    return ts[1:]

def _p_message(ts):
    content = []

    while len(ts):
        sec, ts = _p_section(ts)
        content.append(sec)
    
    return { K_CONTENT: content }

def _p_section(ts):
    if ts[0].t == ":Z:":
        if not is_string(ts[1]) or not is_string(ts[2]) :
            raise ValueError("missing zone and/or context in :Z: at"+str(ts[0].p[0]))
        z, ts = _p_zone(ts[3:], ts[1].v, ts[2].v)
        return [ SEC_ZONE, z ], ts
    elif ts[0].t == ":S:":
        if not is_string(ts[1]) or not is_string(ts[2]) :
            raise ValueError("missing zone and/or context in bare :S: at"+str(ts[0].p[0]))
        s, ts = _p_shard(ts[3:], ts[1].v, ts[2].v, True)
        return [ SEC_SHARD, s], ts
    elif ts[0].t == ":A:":
        if not is_string(ts[1]) or not is_string(ts[2]) :
            raise ValueError("missing zone and/or context in bare :A: at"+str(ts[0].p[0]))
        a, ts = _p_assertion(ts[3:], ts[1].v, ts[2].v, True)
        return [ SEC_ASSERTION, a ], ts
    else:
        raise ValueError("expected :Z:, :S:, or :A: at "+str(ts[0].p[0]))

def _g_section(sec, indent=0):
    if sec[0] == SEC_ZONE:
        return _g_zone(sec[1], indent)
    elif sec[0] == SEC_SHARD:
        return _g_shard(sec[1], indent)
    elif sec[0] == SEC_ASSERTION:
        return _g_assertion(sec[1], indent)
    else:
        # count be a query or notification, but rzfc doesn't care about these
        return ""

def _p_zone(ts, context_name, zone_name):
    out = { K_SUBJECT_ZONE:    zone_name,
            K_CONTEXT:      context_name,
            K_CONTENT:      [] }

    ts = _consume_symbol(ts, "[")

    # eat content
    while ts[0].t != "]":
        if ts[0].t == ":S:":
            s, ts = _p_shard(ts[1:], context_name, zone_name, False)
            out[K_CONTENT].append(s)
        elif ts[0].t == ":A:":
            a, ts = _p_assertion(ts[1:], context_name, zone_name, False)
            out[K_CONTENT].append(a)
        else:
            raise ValueError("expected :S:, :A:, or ] at "+str(ts[0].p[0]))
    ts = _consume_symbol(ts, "]")

    # and signatures, if present
    out[K_SIGNATURES], ts = _p_signatures(ts)

    return out, ts

def _g_zone(z, indent=0):

    istr = " " * indent * INDENT_LEN
    cstrs = []

    for sec in z[K_CONTENT]:
        if sec[0] == SEC_SHARD:
            cstrs.append(_g_shard(s[1], indent+1))
        elif sec[0] == SEC_ASSERTION:
            cstrs.append(_g_assertion(s[1], indent+1))
        else:
            raise ValueError("illegal content in zone")

    return istr + ":Z: {} {} [\n".format(z[K_CONTEXT], z[K_SUBJECT_ZONE]) +\
        "\n".join(cstrs) + istr + "]\n"


def _p_shard(ts, context_name, zone_name, is_section):
    out = { K_SUBJECT_ZONE:    zone_name,
            K_CONTEXT:      context_name,
            K_CONTENT:      [],
            K_SHARD_RANGE:  [] }

    # check for range
    if ts[0].t == "(":
        ts = ts[1:]
        if is_string(ts[0]):
            out[K_SHARD_RANGE].append(ts[0].v)
            ts = _consume_symbol(ts[1:],",")
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
        ts = _consume_symbol(ts, ")")

    ts = _consume_symbol(ts, "[")

    # eat content
    while ts[0].t != "]":
        if ts[0].t == ":A:":
            a, ts = _p_assertion(ts[1:], context_name, zone_name, False)
            out[K_CONTENT].append(a)
        else:
            raise ValueError("expected :A: or ] at "+str(ts[0].p[0]))
    ts = _consume_symbol(ts, "]")

    # and signatures, if present
    out[K_SIGNATURES], ts = _p_signatures(ts)

    if not is_section:
        del(out[K_SUBJECT_ZONE])
        del(out[K_CONTEXT])

    if (len(out[K_SHARD_RANGE]) < 2 or
        (out[K_SHARD_RANGE][0] is None and
            out[K_SHARD_RANGE][1] is None)):
        del(out[K_SHARD_RANGE])

    return out, ts

def g_shard(s, indent=0):
    pass

def _p_assertion(ts, context_name, zone_name, is_section):
    out = { K_SUBJECT_ZONE:    zone_name,
            K_CONTEXT:      context_name,
            K_OBJECTS:      [] }

    if is_string(ts[0]):
        out[K_SUBJECT_NAME] = ts[0].v
        ts = ts[1:]
    else:
        raise ValueError("Expected assertion subject name at "+str(ts[0].p[0]))

    ts = _consume_symbol(ts, "[")

    # eat object content
    while ts[0].t != "]":
        o, ts = _p_objekt(ts)
        out[K_OBJECTS].append(o)
    ts = _consume_symbol(ts, "]")

    # and signatures, if present
    out[K_SIGNATURES], ts = _p_signatures(ts)

    if not is_section:
        del(out[K_SUBJECT_ZONE])
        del(out[K_CONTEXT])

    return out, ts

def _g_assertion(a, indent=0):
    pass

def _p_objekt(ts):
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

def _p_signatures(ts):
    out = []

    # check for signature
    if len(ts) and ts[0].t == "(":
        ts = ts[1:]
        while ts[0].t != ")":
            s, ts = _p_signature(ts)
            out.append(s)
        ts = _consume_symbol(")")

    return out, ts

def _p_signature(ts):
    ts = _consume_symbol(":sig:", ts)
    if is_string(ts[0].t):
        alg = ALGORITHMS[ts[0].v]
    else:
        raise ValueError("expected signature algorithm at "+str(ts[0].p[0]))

    if is_string(ts[1].t):
        ks = KEYSPACES[ts[1].v]
    else:
        raise ValueError("expected signature keyspace at "+str(ts[0].p[0]))

    if ts[1].t == "VAL_8601":
        st = ts[2].v
    else:
        raise ValueError("expected start of validity at "+str(ts[0].p[0]))

    if ts[2].t == "VAL_8601":
        st = ts[3].v
    else:
        raise ValueError("expected end of validity at "+str(ts[0].p[0]))

    ts = ts[4:]
    hexsig = ""
    while ts[0].t == "VAL_HEX":
        hexsig += ts[0].v
        ts = ts[1:]

    return [ alg, ks, st, et, bytes.fromhex(hexkey) ], ts

def compile(zstr):
    """
    Takes a RAINS zonefile as a string, returns a Python dict suitable for
    serialization as a RAINS message.

    """
    ts, rest = scanner.scan(zstr)
    return _p_message(ts)

def zone_iterator(m):
    """
    Takes a RAINS message as a Python dict, iterates over zones (and only zones)
    in the message toplevel.
    
    """

    for section in m[K_CONTENT]:
        if section[0] == SEC_ZONE:
            yield section

def shard_iterator(m):
    """
    Takes a RAINS message as a Python dict, iterates over shards, whether in the
    message toplevel or contained within zones. Contained shards will be made
    complete by filling in context and zone.

    """

    pass

def assertion_iterator(m):
    """
    Takes a RAINS message as a Python dict, iterates over assertions, whether in
    the message toplevel or contained within zones or shards. Contained
    assertions will be made complete by filling in context and zone.

    """

    pass


def shardify(z, count=None, size=None):
    """
    Takes a Python dict structure containing a parsed zone, and either a
    shard count or a maximum shard size, and splits the zone into shards,
    returning the modified structure.

    """
    pass

def sign(m, cipher, private_key, validity_start, validity_end):
    """
    Takes a Python dict structure containing a RAINS message, and signs every
    zone, shard, and assertion within the message, returning the modified
    message.

    """
    pass

def decompile(m):
    """
    Takes a RAINS message as a Python dict, returns a pretty-printed zonefile
    as a string

    """
    mstr = ""

    for sections in z[K_CONTENT]:
        mstr += _g_section(section)
    
    return mstr
        

def shardify(z, count=None, size=None):
    """
    Takes a Python dict structure containing a parsed zone, and either a
    shard count or a maximum shard size, and splits the zone into shards,
    returning the modified structure.

    """
    pass

test_zone_1 = """
:Z: . example.com [
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