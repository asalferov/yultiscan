import os
import re
import sys
from time import sleep


def file_list_gen(search_path, ext=''):
    """Generates and returns a list of all files in given path with option
        to recurse through nested directories. Extension can be provided
        optionally.
    """

    file_list = list()

    # Confirm file path exists
    print(f'Checking {search_path}')
    sleep(.2)
    if not os.path.exists(search_path):
        sys.exit('Specified path does not exist')
    else:
        print(f'Path found\nSearching for {ext} Files')
        sleep(.2)
    # Look for directories
    if any(i.is_dir() for i in os.scandir(search_path)):
        while True:
            recurse = input('Directories found within path. Recurse?\n(Y/N): ')
            # Search recursively or locally based on user input
            if recurse.lower() == 'y':
                recursive_search(search_path, file_list, ext)
                break
            elif recurse.lower() == 'n':
                local_search(search_path, file_list, ext)
                break
            else:
                pass
    else:
        # If no directories found, just do local search
        local_search(search_path, file_list, ext)

    return file_list


"""
Local and recursive search functions
"""


def recursive_search(starting_path, file_dict, ext=''):
    print(f'Searching in {starting_path}')
    sleep(.0005)
    # Find and add files to file list
    local_search(starting_path, file_dict, ext)
    # Loop through non-hidden directories and recurse
    for nested_dir in filter(lambda x: x.is_dir() and not x.name.startswith('.'),
                             os.scandir(starting_path)):
        recursive_search(nested_dir.path, file_dict, ext)
    return


def local_search(local_path, file_dict, ext=''):
    # Find and add files to file list
    for entry in filter(lambda x: x.is_file() and x.name.endswith(ext),
                        os.scandir(local_path)):
        print(f'Adding {entry.path}')
        sleep(.0005)
        file_dict.append(entry.path)
    return
