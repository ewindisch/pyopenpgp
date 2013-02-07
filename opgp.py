#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

#    Copyright 2011 Cloudscaling Group, Inc
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import re
import struct
import sys
import time

"""
Reference material from rfc-2440:

I = implemented
N = needs implementation

Packet types:
       0        -- Reserved - a packet tag must not have this value
       1        -- Public-Key Encrypted Session Key Packet
I      2        -- Signature Packet
       3        -- Symmetric-Key Encrypted Session Key Packet
       4        -- One-Pass Signature Packet
N      5        -- Secret Key Packet
I      6        -- Public Key Packet
       7        -- Secret Subkey Packet
       8        -- Compressed Data Packet
       9        -- Symmetrically Encrypted Data Packet
       10       -- Marker Packet
       11       -- Literal Data Packet
       12       -- Trust Packet
       13       -- User ID Packet
       14       -- Public Subkey Packet
       60 to 63 -- Private or Experimental Values
"""


def mpi(buf):
    """http://tools.ietf.org/html/rfc4880#section-3.2"""
    length = struct.unpack(">H", buf[0:2])[0]
    to_padded_hex = lambda n: '%0.2X' % ord(n)
    inhexstr = ''.join(map(to_padded_hex, buf[2:2 + length]))
    return (int('0x' + inhexstr, 0), ((length + 7) / 8) + 2)


def get_packet_header(raw_data):
    header = ord(raw_data[0])
    fbval = header - 192
    if (header >> 6) == 3:  # New format
        tag = header - 192
        bl_header = ord(raw_data[1])

        if bl_header < 192:
            return (tag, bl_header, 2)
        elif bl_header > 191 and bl_header < 8384:
            raw_length = struct.unpack('>H', raw_data[1:2])[0]
            length = (raw_length ^ 49152) + 192
            return (tag, length, 3)
        elif bl_header == 255:
            length = struct.unpack('>L', raw_data[2:6])[0]
            return (tag, length, 6)
        else:
            raise Exception("Streaming? Can't handle this yet.")
    elif (header >> 6) == 2:  # Old format
        tag = (0b00111100 & header) >> 2
        ltype = 0b00000011 & header

        if ltype == 3:
            return (tag, len(raw_data) - 1, 1)
        elif ltype == 2:
            length = struct.unpack('>L', raw_data[1:5])[0]
            return (tag, length, 5)
        elif ltype < 2:
            fmt = ('>B', '>H')[ltype == 1]
            octets = ltype + 1
            length = struct.unpack(fmt, raw_data[1:1 + octets])[0]
            return (tag, length, ltype + 2)
        raise Exception("Invalid length type.")
    raise Exception("Invalid Packet")


def build_packet_index(raw_data):
    index = []
    ptr = 0
    while ptr < len(raw_data):
        (tag, length, skip) = get_packet_header(raw_data[ptr:])

        if tag == 0:
            raise Exception("Invalid Format")

        index.append((tag, ptr + skip, length))
        ptr += skip + length
    return index


class SignatureSubpacket(object):
    def __init__(self, tag, data):
        self.data = data
        self.tag = tag

    def tag(self):
        return tag

    def value(self):
        return self.data

    @staticmethod
    def get_header(pkt_data):
        """Get a subpacket header from pkt_data."""
        """http://tools.ietf.org/html/rfc4880#section-5.2.3.1"""
        oct1 = ord(pkt_data[0])
        ptr = 0
        if oct1 < 192:
            length = oct1
            ptr += 1
        elif oct1 >= 192 and oct1 < 255:
            raw_length = struct.unpack('>H', pkt_data[0:2])[0]
            length = (raw_length ^ 49152) + 192
            ptr += 2
        elif oct1 == 255:
            length = struct.unpack('>L', raw_data[1:5])[0]
            ptr += 5

        """
        N == "need"
        R == to support revocations
        ? == uncertain requirement

        The value of the subpacket type octet may be:
        N   2 = Signature Creation Time
        N   3 = Signature Expiration Time
            4 = Exportable Certification
        N   5 = Trust Signature
            6 = Regular Expression
        R   7 = Revocable
        ?   9 = Key Expiration Time
           10 = Placeholder for backward compatibility
           11 = Preferred Symmetric Algorithms
        R  12 = Revocation Key
           16 = Issuer
           20 = Notation Data
        ?  21 = Preferred Hash Algorithms
           22 = Preferred Compression Algorithms
           23 = Key Server Preferences
           24 = Preferred Key Server
           25 = Primary User ID
           26 = Policy URI
           27 = Key Flags
           28 = Signer's User ID
           29 = Reason for Revocation
           30 = Features
        R  31 = Signature Target
        ?  32 = Embedded Signature
           100 To 110 = Private or experimental
        """
        pkt_type = ord(raw_data[ptr])
        # ptr is the offset the subpacket data begins.
        return (pkt_type, length, ptr + 1)


class SignatureSubpacketArray(object):
    #def build_subpacket_index(raw_data):
    def __init__(self, raw_data):
        super(SignatureSubpacketArray, self).__init__()

        index = []
        ptr = 0
        while ptr < len(raw_data):
            (tag, length, skip) = SignatureSubpacket.get_header(raw_data[ptr:])

            if tag == 0:
                raise Exception("Invalid Format")

            index.append((tag, ptr + skip, length))
            ptr += skip + length

        self.data = raw_data
        self.pkt_index = index

    def __iter__(self):
        for tag, seek, length in self.pkt_index:
            yield SignatureSubpacket(tag, self.data[seek:seek + length])

    def __getitem__(self, i):
        (tag, seek, length) = self.pkt_index[i]
        return SignatureSubpacket(tag, self.data[seek:seek + length])


class Packet(object):
    pass


class SignaturePacket(Packet):
    def __init__(self, pkt_data):
        try:
            version = struct.unpack('>B', pkt_data[0])[0]
        except:
            raise Exception("Invalid Packet")

        self.version = version

        if version == 3:
            """http://tools.ietf.org/html/rfc4880#section-4.3"""
            (hash_length, sig_type, created_at, key_id, algo, left16) = \
                struct.unpack('>BBIQBBH', pkt_data[1:14])
            ptr = 15

            if hash_length != 5:
                raise Exception("Hash length must be 5 per RFC.")
        elif version == 4:
            """http://tools.ietf.org/html/rfc4880#section-5.2.3"""
            (sig_type, algo, hash_algo, l_hashed_subpkts) = \
                struct.unpack('>BBBH', pkt_data[1:6])
            ptr = 7

            # skip hashed subpkts for now.
            #ptr += l_hashed_subpkts
            #hashed_subpkt_index = build_subpacket_index(pkt_data[ptr:ptr +
            #                                                     l_hashed_subpkts])
            hashed_subpkts = SignatureSubpacketArray(pkt_data[ptr: ptr + l_hashed_subpkts])
            ptr += l_hashed_subpkts

            l_unhashed_subpkts = struct.unpack('>H', pkt_data[ptr:ptr+2])[0]
            ptr += 2

            # skip unhashed subpkts for now
            ptr += l_unhashed_subpkts
        else:
            raise Exception("Unknown signature packet version.")

        """Signature types:
           - http://tools.ietf.org/html/rfc4880#section-5.2.1
        """
        self.signature_type = sig_type

        # extract integers comprising the key material.
        ptr = 15
        algo_fields = []
        algoname = None
        if algo in (1, 2, 3):  # rsa
            """
            Algorithm-Specific Fields for RSA signatures:
             - multiprecision integer (MPI) of RSA signature value m**d mod n.
            """
            algoname = "RSA"
            (rsa_sig, seek) = mpi(pkt_data[ptr:]); ptr += seek
            algo_fields.append(rsa_sig)
        elif algo == 17:  # dsa
            """
            Algorithm-Specific Fields for DSA signatures:
             - MPI of DSA value r;  MPI of DSA value s.
            """
            algoname = "DSA"
            (r, seek) = mpi(pkt_data[ptr:]); ptr += seek
            (s, seek) = mpi(pkt_data[ptr:]); ptr += seek
            algo_fields = (r, s)

        self._algotag = algo
        self._algoname = algoname
        self._signature = algo_fields
        self._hashed_subpkts = hashed_subpkts

    def algorithm(self):
        """RSA or DSA"""
        return self._algoname

    def tag(self):
        return self._aglotag

    def signature(self):
        """
           Return signature.
            if rsa: value m**d mod n
            if dsa: (r, s)
        """
        return self._signature

    def hashed_subpackets(self):
        return self._hashed_subpkts


def read_public_key_packet(pkt_data):
    """http://tools.ietf.org/html/rfc4880#section-5.5.2"""
    (ver, created_at, algo) = struct.unpack('>BIB', pkt_data[0:6])
    if ver != 4:
        raise("Cannot handle versions other than 4 yet (i.e. ver 3)")

    """
    9.1. Public Key Algorithms

           ID           Algorithm
           --           ---------
           1          - RSA (Encrypt or Sign)
           2          - RSA Encrypt-Only
           3          - RSA Sign-Only
           16         - Elgamal (Encrypt-Only), see [ELGAMAL]
           17         - DSA (Digital Signature Standard)
           18         - Reserved for Elliptic Curve
           19         - Reserved for ECDSA
           20         - Elgamal (Encrypt or Sign)
    """
    # extract integers comprising the key material.
    if algo in (1, 2, 3):  # rsa
        """
        Algorithm-Specific Fields for RSA public keys:
        - multiprecision integer (MPI) of RSA public modulus n;
        - MPI of RSA public encryption exponent e.
        """
        ptr = 7
        (n, seek) = mpi(pkt_data[ptr:]); ptr += seek
        (e, seek) = mpi(pkt_data[ptr:]); ptr += seek
        #print "RSA n=%i, e=%i" % (n, e)
    elif algo == 17:  # dsa
        """
        Algorithm-Specific Fields for DSA public keys:
         - MPI of DSA prime p;
         - MPI of DSA group order q (q is a prime divisor of p-1);
         - MPI of DSA group generator g;
         - MPI of DSA public-key value y (= g**x mod p where x
           is secret).
        """
        ptr = 7
        (p, seek) = mpi(pkt_data[ptr:]); ptr += seek
        (q, seek) = mpi(pkt_data[ptr:]); ptr += seek
        (g, seek) = mpi(pkt_data[ptr:]); ptr += seek
        (y, seek) = mpi(pkt_data[ptr:]); ptr += seek
        #print "DSA params:\nP: %s,\nQ: %s,\nG: %s,\nY: %s" % (p, q, g, y)
    elif algo == 20:
        """
        Algorithm-Specific Fields for Elgamal public keys:
         - MPI of Elgamal prime p;
         - MPI of Elgamal group generator g;
        """
        raise Exception("Elgamal not supported.")

    return (ver, created_at, algo)


def unarmor(pgp_msg):
    """Return raw OpenPGP packet data"""
    pgp_header_re = re.compile(r'^-----.*-----', re.M)
    matches = pgp_header_re.finditer(pgp_msg)

    # Stuff between the - indicators.
    pgp_msg_start = matches.next().end() + 1
    pgp_msg_end = matches.next().start() - 1
    pgp_msg = pgp_msg[pgp_msg_start:pgp_msg_end]

    # Radix64 starts after two newlines.
    # TODO(ewindisch): support carriage returns?
    start_base64 = pgp_msg.find('\n\n') + 2
    b64data = pgp_msg[start_base64:]

    raw_data = base64.b64decode(b64data)
    return raw_data

if __name__ == "__main__":
    key_lines = sys.stdin.readlines()
    pgp_msg = ''.join(key_lines)
    raw_data = unarmor(pgp_msg)

    pkt_index = build_packet_index(raw_data)

    # for each packet where tag == 6 (public key)
    # each packet looks like (ptr, tag, length)
    for pub_key_pkt in [(x, y, z) for x, y, z in pkt_index if x == 6]:
        print read_public_key_packet(raw_data[pub_key_pkt[1]:pub_key_pkt[1]+pub_key_pkt[2]])

    # for each packet where tag == 2 (signature)
    # each packet looks like (tag, ptr, length)
    for pub_key_pkt in [(x, y, z) for x, y, z in pkt_index if x == 2]:
        print pub_key_pkt
        print "Signature packet:"
        sp = SignaturePacket(raw_data[pub_key_pkt[1]:pub_key_pkt[1]+pub_key_pkt[2]])

        print "Signature version: %i" % sp.version
        print "Signature type: %i" % sp.signature_type
        print "Signature uses %s" % sp.algorithm()

        print "-----START SIGNATURE-----"
        print map(base64.b64encode, map(str, sp.signature()))
        print "----- END  SIGNATURE-----"

        print "Subpackets:"
        for pkt in sp.hashed_subpackets():
            print "-----SUBPACKET START-----"
            print base64.b64encode(pkt.value())
            print "-----SUBPACKET   END-----"
