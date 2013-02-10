======
passph
======

Password pre-hasher.

passph provides an approach to keeping the level of password strength
consistent, while not sacrificing memorability and eliminating the
possibility of pattern detection in case passwords are compromised.

This tool may introduce other security risks if used incorrectly.
(Use at your own risk!)

Copy-to-clipboard (-c) functionality available for:
  Systems with X (via xclip); Android; Windows; OSX

Dependencies
------------
  - Python 2.6 and up, or Python 3. Argparse will only work with 2.7 and up.
  - Optional: xclip for copying to the clipboard on systems with X.
  - Optional: SL4A Python for use on Android platform.

Usage
-----

.. code-block::

    usage: passph.py [-h] [-c] [-p] [-u URL] [-i C] [-l CHARS] [-A] [-e]
                     [--show-entropy] [-v]

    Password Pre-Hasher: Use at your own risk! By default the program does NOT
    output anything, please choose from available options.

    optional arguments:
      -h, --help            show this help message and exit
      -c, --clip            Copy result to available clipboard.
      -p, --print           Print to stdout.
      -u URL, --salt-url URL
                            Use contents at URL as salt.
      -i C, --iterations C  Iterations of PBKDF2. [Default: 8000]
      -l CHARS, --length CHARS
                            Length of result. [Default: 25]
      -A, --alt-charlist    Use alternative charlist, from either environment
                            variable PASSPH_CHARLIST or a preset builtin.
      -e, --echo            Echo passwords/passphrases.
      --show-entropy        Show estimated output password entropy.
      -v, --version         show program's version number and exit

