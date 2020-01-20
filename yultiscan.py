"""
yultiscan

A command-line wrapper for compiling multiple Yara rule files on the spot
and testing them against a given directory/filepath, with the option to
multithread.

Usage:
    yultiscan.py [-t | --threads=<NUM>] <path-to-rules> <path-to-scan>
    yultiscan.py -h | --help
    yultiscan.py --version

Options:
    -t --threads=<NUM>  Number of threads to use: default=1
    -h --help           Show this screen
    --version           Show version

"""

from yultiscan.docopt import docopt
def main():
    """"""
    from yultiscan.scripts import utils
    options = docopt(__doc__, version='1.0.0')


