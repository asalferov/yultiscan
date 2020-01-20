"""
yultiscan

A command-line wrapper for compiling multiple Yara rule files on the spot
and testing them against a given directory/filepath, with the option to
multithread.

Usage:
    yultiscan.py [options] <path-to-rules> <path-to-scan>
    yultiscan.py -h | --help
    yultiscan.py --version

Options:
    -t --threads=<NUM>      Number of threads to use: [default=1]
    -c --compile-dir=<DIR>  Directory to compile ruleset: [default=current directory]
    -h --help               Show this screen
    --version               Show version

"""

from docopt import docopt
import scanner
import utils


if __name__ == '__main__':
    args = docopt(__doc__, version='1.0.0')
    print(args)

    if args['--threads']:
        thread_num = int(args['--threads'])
    else:
        thread_num = 1
    if args['--compile-dir']:
        compile_dir = args['--compile-dir']
    else:
        compile_dir = '.'

    rules_obj = utils.compile_yars(args['<path-to-rules>'], compile_dir)
    file_list = utils.file_list_gen(args['<path-to-scan>'])
    scanner.Scanner(rules_obj, file_list, thread_num)


