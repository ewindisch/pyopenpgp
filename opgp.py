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


def subpacket_multi(unpack_fmt, octets, data):
    try:
        return struct.unpack(unpack_fmt, data[:octets - 1][0])
    except:
        raise Exception("Signature Subpacket not recognized or type unknown.")


def subpacket_scalar(*args):
    return subpacket_multi(*args)[0]


def subpacket_bool(*args):
    value = subpacket_scalar(*args)
    try:
        return (False, True)[value]
    except IndexError:
        raise TypeError("Expected boolean value. Value not boolean.")


def subpacket_array(unpack_fmt, data):
    return [ struct.unpack(unpack_fmt, b)[0] for b in data ]


def subpacket_string(data):
    return str(bytearray(subpacket_array('>c', data)))


def subpacket_unsupported(*args):
    raise NotImplementedError("Subpacket type unsupported.")


def subpacket_reason_revoke(data):
    return (subpacket_scalar('>I', 1, data[0]),
            subpacket_string(data[1:]))


def subpacket_embedded(data):
    return SignaturePacket(data)


class SignatureSubpacket(object):
    SPTAGTABLE = map(lambda x: None, range(0, 33))  # Initialize with None
    SPTAGTABLE[2] = ["Signature Creation Time", subpacket_scalar, '>I', 4]
    SPTAGTABLE[3] = ["Signature Expiration Time", subpacket_scalar, '>I', 4]
    SPTAGTABLE[4] = ["Exportable Certification", subpacket_bool, '>B', 1]
    SPTAGTABLE[5] = ["Trust Signature", subpacket_multi, '>BB', 2]
    SPTAGTABLE[6] = ["Regular Expression", subpacket_unsupported]
    SPTAGTABLE[7] = ["Revocable", subpacket_bool, '>B', 1]
    SPTAGTABLE[9] = ["Key Expiration Time", subpacket_scalar, '>I', 4]
    SPTAGTABLE[11] = ["Preferred Symmetric Algorithms", subpacket_array, '>B']
    SPTAGTABLE[12] = ["Revocation Key", subpacket_unsupported]
    SPTAGTABLE[16] = ["Issuer", subpacket_scalar, '>Q', 8]
    SPTAGTABLE[20] = ["Notation Data", subpacket_unsupported]
    SPTAGTABLE[21] = ["Preferred Hash Algorithms", subpacket_array, '>B']
    SPTAGTABLE[22] = ["Preferred Compression Algorithms",
                      subpacket_array, '>B']
    SPTAGTABLE[23] = ["Key Server Preferences", subpacket_array, '>B']
    SPTAGTABLE[24] = ["Preferred Key Server", subpacket_string]
    SPTAGTABLE[25] = ["Primary User ID", subpacket_bool, '>B', 1]
    SPTAGTABLE[26] = ["Policy URI", subpacket_string]
    SPTAGTABLE[27] = ["Key Flags", subpacket_array, '>B']
    SPTAGTABLE[28] = ["Signer's User ID", subpacket_string]
    SPTAGTABLE[29] = ["Reason for Revocation", subpacket_reason_revoke]
    SPTAGTABLE[30] = ["Features", subpacket_array, '>B']
    SPTAGTABLE[31] = ["Signature Target", subpacket_unsupported]
    SPTAGTABLE[32] = ["Embedded Signature", subpacket_embedded]

    def __init__(self, tag, data, critical=False):
        self._data = data
        self._tag = tag
        self._critical = critical

    def tag(self):
        return self._tag

    def name(self):
        return SignatureSubpacket.SPTAGTABLE[self._tag][0]

    def value(self):
        # Call mapped function (index 1),
        # optionally with arguments (index 2+),
        # always passing self.data as the last argument.
        entry = SignatureSubpacket.SPTAGTABLE[self._tag]

        if entry == None:
            if self._critical:
                raise Exception("Critical packet unsupported.")
            return ''

        args = entry[len(entry) > 1 and 2 or 1:]
        args.append(self.data)

        try:
            entry[1](*args)
        except NotImplementedError:
            if self._critical:
                raise

    @staticmethod
    def get_header(pkt_data):
        """Get a subpacket header from pkt_data."""
        """http://tools.ietf.org/html/rfc4880#section-5.2.3.1"""
        oct1 = ord(pkt_data[0])
        ptr = 0
        if oct1 < 192:
            print "Small subpacket"
            length = oct1
            ptr += 1
        elif oct1 >= 192 and oct1 < 255:
            print "Medium subpacket"
            raw_length = struct.unpack('>H', pkt_data[0:2])[0]
            length = (raw_length ^ 49152) + 192
            ptr += 2
        elif oct1 == 255:
            print "Large subpacket"
            length = struct.unpack('>L', raw_data[1:5])[0]
            ptr += 5

        raw_tag = ord(raw_data[ptr])
        critical = raw_tag >> 7
        tag = (raw_tag | 128) - 128
        #tag = struct.unpack(">B", raw_data[ptr])[0]
        # ptr is the offset the subpacket data begins.
        return (tag, critical, ptr + 1, length)


class SignatureSubpacketArray(object):
    #def build_subpacket_index(raw_data):
    def __init__(self, raw_data):
        super(SignatureSubpacketArray, self).__init__()

        index = []
        ptr = 0
        while ptr < len(raw_data):
            (tag, critical, header_size, data_size) = \
                SignatureSubpacket.get_header(raw_data[ptr:])

            # tag, start, end
            index.append((tag, critical, ptr + header_size, data_size))
            ptr += header_size + data_size

        self.data = raw_data
        self.pkt_index = index

    def __iter__(self):
        for tag, critical, seek, length in self.pkt_index:
            print "tag, seek, length: %s, %s, %s" % (tag, seek, length)
            yield SignatureSubpacket(tag, self.data[seek:seek + length],
                                     critical=critical)

    def __getitem__(self, i):
        (tag, critical, seek, length) = self.pkt_index[i]
        return SignatureSubpacket(tag, self.data[seek:seek + length],
                                  critical=critical)


class Packet(object):
    pass


class SignaturePacket(Packet):
    def __init__(self, pkt_data):
        try:
            version = struct.unpack('>B', pkt_data[0])[0]
        except:
            raise Exception("Invalid Packet")

        self.version = version
        ptr = 1

        if version == 3:
            """http://tools.ietf.org/html/rfc4880#section-4.3"""
            (hash_length, sig_type, created_at, key_id, algo, left16) = \
                struct.unpack('>BBIQBBH', pkt_data[ptr:14])
            ptr += 14

            if hash_length != 5:
                raise Exception("Hash length must be 5 per RFC.")
        elif version == 4:
            """http://tools.ietf.org/html/rfc4880#section-5.2.3"""
            (sig_type, algo, hash_algo, l_hashed_subpkts) = \
                struct.unpack('>BBBH', pkt_data[ptr:6])
            ptr += 6

            hashed_subpkts = SignatureSubpacketArray(
                    pkt_data[ptr:ptr + l_hashed_subpkts])
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
        print read_public_key_packet(
            raw_data[pub_key_pkt[1]:pub_key_pkt[1]+pub_key_pkt[2]])

    # for each packet where tag == 2 (signature)
    # each packet looks like (tag, ptr, length)
    for pub_key_pkt in [(x, y, z) for x, y, z in pkt_index if x == 2]:
        print pub_key_pkt
        print "Signature packet:"
        sp = SignaturePacket(
            raw_data[pub_key_pkt[1]:pub_key_pkt[1]+pub_key_pkt[2]])

        print "Signature version: %i" % sp.version
        print "Signature type: %0.2X" % sp.signature_type
        print "Signature uses %s" % sp.algorithm()

        print "-----START SIGNATURE-----"
        print map(base64.b64encode, map(bytes, sp.signature()))
        print "----- END  SIGNATURE-----"

        print "Subpackets:"
        for pkt in sp.hashed_subpackets():
            print "-----SUBPACKET START-----"
            print pkt.tag()
            print base64.b64encode(pkt.value())
            print "-----SUBPACKET   END-----"
