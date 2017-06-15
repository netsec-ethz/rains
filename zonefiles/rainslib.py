#
# rainslib: Python 3 implementation of CBOR and Zonefile datamodels for RAINS 
#

"""
This module implements Python objects for the RAINS data model which are capable of rendering themselves as CBOR, zonefiles, and signing strings; and parsing themselves from CBOR and zonefiles.

"""

class Zone:

    def __init__(self, context=None, subject=None):
        self._context = context
        self._subject = subject 
        self._contents = []

    def 

class Shard:
    def __init__(self, context=None, subject=None, container=None):
        if container is None:
            self._context = context
            self._subject = subject
        else:
            self._context = container._context
            self._subject = container._subject
        self._range = []
        self._objects = []

    def _natural_range(self):
        """
        Return the (inclusive) range of names for this shard

        """
        pass

    def range(self):
        # ask the zone to order its shards, then get the range from previous and next shard.
        # if no container, use natural range.
        pass

    def zone_entry(self):
        pass

    def signing_form(self):
        pass

class Assertion:
    def __init__(self, context=None, subject=None, container=None):
        if container is None:
            self._context = context
            self._subject = subject
        else:
            self._context = container._context
            self._subject = container._subject
        self._objects = []

class Object:
    def __init__(self, type, value):
        self._type = type

class Query:
    pass


