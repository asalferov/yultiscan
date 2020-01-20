"""
Local and recursive search functions
"""

import os
from time import sleep


def recursive_search(starting_path, file_dict, ext=''):
    print(f'Searching in {starting_path}')
    sleep(.2)
    # Find and add .yar files to file list
    local_search(starting_path, file_dict, ext)
    # Loop through non-hidden directories and recurse
    for nested_dir in filter(lambda x: x.is_dir() and not x.name.startswith('.'),
                             os.scandir(starting_path)):
        recursive_search(nested_dir.path, file_dict, ext)
    return


def local_search(search_path, file_dict, ext=''):
    for entry in filter(lambda x: x.is_file() and ext in x.name,
                        os.scandir(search_path)):
        print(f'Adding {entry.path}')
        sleep(.0005)
        file_dict.append(entry.path)
    return
