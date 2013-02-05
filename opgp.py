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
import time

"""
Reference material from rfc-2440:

Packet types:
       0        -- Reserved - a packet tag must not have this value
       1        -- Public-Key Encrypted Session Key Packet
       2        -- Signature Packet
       3        -- Symmetric-Key Encrypted Session Key Packet
       4        -- One-Pass Signature Packet
       5        -- Secret Key Packet
       6        -- Public Key Packet
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

def get_header(raw_data):
    header = ord(raw_data[0])
    fbval = header - 192
    if (header >> 6) == 3:  # New format
        tag = header - 192
        bl_header = ord(raw_data[1])

        if bl_header < 192:
            print "NewSmall"
            return (tag, bl_header, 2)
        elif bl_header > 191 and bl_header < 8384:
            print "NewMedium"
            raw_length = struct.unpack('>H', raw_data[1:2])[0]
            length = (raw_length ^ (192 << 8)) + 192
            return (tag, length, 3)
        elif bl_header == 255:
            print "NewLarge"
            length = struct.unpack('>L', raw_data[2:6])[0]
            return (tag, length, 6)
        else:
            raise Exception("Streaming? Can't handle this yet.")
    elif (header >> 6) == 2:  # Old format
        tag = (0b00111100 & header) >> 2
        ltype = 0b00000011 & header

        if ltype == 3:
            print "OldLarge"
            return (tag, len(raw_data) - 1, 1)
        elif ltype == 2:
            print "OldMedium"
            length = struct.unpack('>L', raw_data[1:5])[0]
            return (tag, length, 5)
        elif ltype < 2:
            print "OldSmall"
            fmt = ('>B', '>H')[ltype == 1]
            octets = ltype + 1
            length = struct.unpack(fmt, raw_data[1:1+octets])[0]
            return (tag, length, ltype+2)
        raise Exception("Invalid length type.")
    raise Exception("Invalid Packet")


def build_index(raw_data):
    index = []
    ptr = 0
    print "Length raw_data in octets: %i" % len(raw_data)
    while ptr < len(raw_data):
        (tag, length, skip) = get_header(raw_data[ptr:])

        if tag == 0:
            raise Exception("Invalid Format")

        index.append((ptr + skip, tag, length))
        ptr += skip + length
    return index


def read_packet(pkt_data):
    """
    A version 4 packet contains:
     - A one-octet version number (4).
     - A four-octet number denoting the time that the key was created.
     - A one-octet number denoting the public-key algorithm of this key.
     - A series of multiprecision integers comprising the key material.
       This algorithm-specific portion is:
       Algorithm-Specific Fields for RSA public keys:
         - multiprecision integer (MPI) of RSA public modulus n;
         - MPI of RSA public encryption exponent e.
       Algorithm-Specific Fields for DSA public keys:
         - MPI of DSA prime p;
         - MPI of DSA group order q (q is a prime divisor of p-1);
         - MPI of DSA group generator g;
         - MPI of DSA public-key value y (= g**x mod p where x
           is secret).
       Algorithm-Specific Fields for Elgamal public keys:
         - MPI of Elgamal prime p;
         - MPI of Elgamal group generator g;
    """
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
    rsa = algo in (1, 2, 3)
    dsa = algo == 17
    elgamal = algo == 20

    return (ver, created_at, algo)


def unarmor(pgp_msg):
    """Return raw OpenPGP packet data"""
    pgp_header_re = re.compile(r'^-----.*-----', re.M)
    matches = pgp_header_re.finditer(pgp_msg)

    # Stuff between the - indicators.
    pgp_msg_start = matches.next().end()+1
    pgp_msg_end = matches.next().start()-1
    pgp_msg = pgp_msg[pgp_msg_start:pgp_msg_end]

    # Radix64 starts after two newlines.
    # TODO(ewindisch): support carriage returns?
    start_base64 = pgp_msg.find('\n\n') + 2
    b64data = pgp_msg[start_base64:]

    raw_data = base64.b64decode(b64data)
    return raw_data

if __name__ == "__main__":
    # Assume input is half-armored.
    # base-64, with all other armoring stripped.
    # ignore checksum.

    with open('full-block-example.asc') as key_fh:
        key_lines = key_fh.readlines()

    pgp_msg = ''.join(key_lines)
    raw_data = unarmor(pgp_msg)

    pkt_index = build_index(raw_data)

    # for each packet where tag == 6
    # each packet looks like (ptr, tag, length)
    for pub_key_pkt in [ (x, y, z) for x, y, z in pkt_index if y == 6 ]:
        print read_packet(raw_data[pub_key_pkt[0]:pub_key_pkt[2]])
