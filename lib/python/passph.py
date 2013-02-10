#!/usr/bin/env python

# Copyright (c) 2012 - 2013, Marco Elver
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the
#    distribution.
#
#  * Neither the name of the software nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

##
# @file passph.py
# Password pre-hasher.
#
# passph provides an approach to keeping the level of password strength
# consistent, while not sacrificing memorability and eliminating the
# possibility of pattern detection in case passwords are compromised.
#
# This tool may introduce other security risks if used incorrectly.
# (Use at your own risk!)
#
# Copy-to-clipboard (-c) functionality available for:
#   Systems with X (via xclip); Android; Windows; OSX
#
# Dependencies:
#   - Python 2.6 and up, or Python 3. Argparse will only work with 2.7 and up.
#   - Optional: xclip for copying to the clipboard on systems with X.
#   - Optional: SL4A Python for use on Android platform.
#
# @author Marco Elver <me AT marcoelver.com>
#

__version__ = "20130130"

import sys
import os
import hashlib
import json
import math
import hmac
import struct
import binascii

try:
    import argparse
except:
    argparse = None

try:
    from urllib.request import urlopen
    big_int = int
except:
    # Python 2
    import urllib2
    import contextlib
    urlopen = lambda url: contextlib.closing(urllib2.urlopen(url))
    input = raw_input
    big_int = long

try:
    import android
    input = lambda msg: droid.dialogGetInput(msg).result
    getpass = lambda msg: droid.dialogGetPassword(msg).result
    clipboard_set = lambda data: droid.setClipboard(data)
except:
    android = None
    import subprocess
    from getpass import getpass

    if sys.platform.startswith("win") or sys.platform.startswith("cygwin"):
        import ctypes

        GMEM_DDESHARE = 0x2000
        CF_TEXT = 1
        def clipboard_set(data):
            ctypes.windll.user32.OpenClipboard(0)
            ctypes.windll.user32.EmptyClipboard()
            hMem = ctypes.windll.kernel32.GlobalAlloc(GMEM_DDESHARE, len(data)+1)
            pchData = ctypes.windll.kernel32.GlobalLock(hMem)
            ctypes.cdll.msvcrt.strcpy(ctypes.c_char_p(pchData), data)
            ctypes.windll.kernel32.GlobalUnlock(hMem)
            ctypes.windll.user32.SetClipboardData(CF_TEXT, hMem)
            ctypes.windll.user32.CloseClipboard()
    elif sys.platform.startswith("darwin"):
        def clipboard_set(data):
            pbcopy = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            pbcopy.communicate(input=data)
    else:
        # Assume POSIX system with X and xclip installed
        def clipboard_set(data):
            xclip = subprocess.Popen(["xclip", "-i"], stdin=subprocess.PIPE)
            xclip.communicate(input=data)

DIGEST = hashlib.sha512

# List of characters allowed in generated passwords; length must be power of 2.
# Repeating characters will make the encoding irreversable and non-unique
# (collisions).
#
# Since not all printable ASCII characters can always be used in a password, I
# chose the most likely accepted characters; I didn't want to limit the
# characters to 64, but since the next higher valid radix is 128, needed to
# duplicate some characters. For this application it is, to best of my
# knowledge, not a problem -- in case some of this code is reused for a
# different application, beware!
#
CHARLIST = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" \
           "--__==++;;::,,..!!<<>>##**(()){{}}[[]]@@??%%&&//0123456789abcdABCD"
PAD_CHAR = "$"

def base_charlist_encode(data, charlist):
    """
    Constructs a radix-(2^N) representation of data from charlist, where
    charlist is of length 2^N. (like base64)
    """
    if (len(charlist) & (len(charlist) - 1)) != 0:
        raise Exception("charlist length is not a power of 2")

    bits_per_digit = int(math.floor(math.log(len(charlist), 2)))
    cur_bits = 0
    cur_index = 0
    indices = []
    # Note: For Py3k only, bytearray would not be necessary
    for b in bytearray(data):
        remain_bits = 8
        while remain_bits != 0:
            use_bits = min(remain_bits, bits_per_digit - cur_bits)
            use_b = (b >> (remain_bits - use_bits)) & ((2 ** use_bits) - 1)
            remain_bits -= use_bits
            cur_bits += use_bits
            cur_index = cur_index | (use_b << (bits_per_digit - cur_bits))

            if cur_bits == bits_per_digit:
                indices.append(cur_index)
                cur_bits = 0
                cur_index = 0

    result = "".join(charlist[idx] for idx in indices)
    if cur_bits != 0:
        result += charlist[cur_index] + (PAD_CHAR * (bits_per_digit - cur_bits))

    return result

def pbkdf2(password, salt, iter_count, dk_len=None, digest=hashlib.sha512):
    """
    Implementation of PBKDF2 as defined in RFC 2898.
    Uses HMAC as the PRF.
    """
    h_len = digest().digest_size

    if dk_len is None:
        dk_len = h_len

    if dk_len > ((2**32) - 1) * h_len:
        raise Exception("pbkdf2: derived key too long")

    l = int(math.ceil(float(dk_len) / h_len))
    r = dk_len - (l - 1) * h_len

    unhex_fmt = "{{0:0{0}x}}".format(h_len*2)

    def F(i):
        u = hmac.new(password, salt + struct.pack(">I", i),
                digestmod=digest).digest()
        F_result = big_int(binascii.hexlify(u), 16)
        for _ in range(1, iter_count):
            u = hmac.new(password, u, digestmod=digest).digest()
            # Performance improvement using only one XOR with Python's long int
            F_result ^= big_int(binascii.hexlify(u), 16)

        return binascii.unhexlify(unhex_fmt.format(F_result).encode())

    Ts = (F(i) for i in range(1, l))
    return b''.join(Ts) + F(l)[:r]

def pre_hash(masterpw, password, args):
    """
    Hashes input with salt using hash function implementation supporting
    the interface as defined in hashlib/hmac.
    """
    salt_hasher = hmac.new(masterpw, digestmod=DIGEST)

    if args.salt_url is not None:
        print("[INFO] Using resource at URL as salt ...")
        with urlopen(args.salt_url) as f:
            while True:
                data = f.read(128)
                if len(data) != 0:
                    salt_hasher.update(data)
                else:
                    break

    key_len = int(math.ceil((math.log(len(CHARLIST), 2) * args.len_chars) / 8))
    key = pbkdf2(password, salt_hasher.digest(),
                 iter_count=args.iterations, dk_len=key_len,
                 digest=DIGEST)
    return base_charlist_encode(key, CHARLIST)

def estimate_entropy(pwlen):
    """
    Estimate password entropy for pre_hash output with given length.
    """
    return pwlen * math.log(len(frozenset(CHARLIST)), 2)

def get_args_cmdline(argv):
    parser = argparse.ArgumentParser(
            description="Password Pre-Hasher: Use at your own risk!\n"\
                        "By default the program does NOT output anything, "\
                        "please choose from available options.")
    parser.add_argument("-c", "--clip", action="store_true",
            dest="do_clip", default=False,
            help="Copy result to available clipboard.")
    parser.add_argument("-p", "--print", action="store_true",
            dest="do_print", default=False,
            help="Print to stdout.")
    parser.add_argument("-u", "--salt-url", metavar="URL", type=str,
            dest="salt_url", default=None,
            help="Use contents at URL as salt.")
    parser.add_argument("-i", "--iterations", metavar="C", type=int,
            dest="iterations", default=8000,
            help="Iterations of PBKDF2. [Default: 8000]")
    parser.add_argument("-l", "--length", metavar="CHARS", type=int,
            dest="len_chars", default=25,
            help="Length of result. [Default: 25]")
    parser.add_argument("-e", "--echo", action="store_true",
            dest="echo", default=False,
            help="Echo passwords/passphrases.")
    parser.add_argument("--show-entropy", action="store_true",
            dest="show_entropy", default=False,
            help="Show estimated output password entropy.")
    parser.add_argument("-v", "--version", action="version",
            version="%(prog)s {0}".format(__version__))

    return parser.parse_args()

def get_args_json(argv):
    class DefaultArgs:
        def __init__(self, entries={}):
            self.do_clip = True # This is different from cmdline default
            self.do_print = False
            self.salt_url = None
            self.iterations = 8000
            self.len_chars = 25
            self.echo = False
            self.show_entropy = False

            self.__dict__.update(entries)

            # Perform type conversions after updating entries

            self.iterations = int(self.iterations)
            self.len_chars = int(self.len_chars)

    try:
        if android is not None:
            jsonfile = open("/sdcard/passph.json")
        else:
            jsonfile = open(argv[1])
    except Exception as e:
        print(e)
        return DefaultArgs()

    try:
        # Fast flexible string concatenation => make generator of strings and join.
        # Read lines and discard comments (// and # works).
        line_gen = (line for line in jsonfile if not (
                line.startswith("//") or line.startswith("#")))

        jsonargs = json.loads(''.join(line_gen))
    finally:
        jsonfile.close()

    return DefaultArgs(jsonargs)

def main(argv):
    if android is not None:
        global droid
        droid = android.Android()

    if argparse is not None and android is None and \
      (len(argv) <= 1 or (len(argv[1]) > 1 and argv[1][0] == "-")):
        args = get_args_cmdline(argv)
    else:
        args = get_args_json(argv)

    if args.echo: pw_input = input
    else:         pw_input = getpass

    result = pre_hash(
                pw_input("[1/2] Enter master password/passphrase: ").encode(),
                pw_input("[2/2] Enter resource password/passphrase: ").encode(),
                args)[:args.len_chars]

    if len(result) < args.len_chars:
        print("[WARNING] Too many characters requested, reduced to {0}".format(len(result)))

    if args.show_entropy:
        print("[INFO] Estimated output password entropy: {0:.2f}".format(
            estimate_entropy(args.len_chars)))

    if args.do_clip:
        print("[INFO] Copying to clipboard")
        clipboard_set(result.encode())

    if args.do_print:
        print(result)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))

