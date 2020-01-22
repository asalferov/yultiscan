import os
import sys
from time import sleep
import yara


def compile_yars(rule_path, compile_path):
    """Combines and compiles .yar files found at given path with option
        to recurse through nested directories. Combines rule
        files into one file - 'all_rules.yar', saved at the path provided or
        current directory by default. Returns compiled yara rules object generated
        from combined rule file.
    """

    # Generate list of yara files
    rule_list = file_list_gen(rule_path, '.yar')
    # Set path to save combined rule file
    all_rule_file = ''.join([compile_path, 'all_rules.yar'])

    # Combine all yara rule files at given path into a single file
    with open(all_rule_file, 'wb') as all_rules:
        print(f'Creating combined rules file: {all_rules.name}')
        for yara_file in rule_list:
            with open(yara_file, 'rb') as file_to_write:
                buf = file_to_write.read()
                all_rules.write(buf)
        all_rules.seek(0)
        all_rules.close()

    print(f'Compiling {all_rule_file}')

    # Attempt to return compiled rules object. Catch errors/warnings
    try:
        return yara.compile(filepath=all_rule_file, includes=False, error_on_warning=False)
    except yara.WarningError as err:
        sys.exit(f'[Compilation] Warning: {err}')
    except yara.SyntaxError as err:
        sys.exit(f'[Compilation] Syntax Error: {err}')
    except yara.Error as err:
        sys.exit(f'[Compilation] Error Occurred: {err}')


def file_list_gen(search_path, ext=''):
    """Generates and returns a list of all files in given path with option
        to interactively recurse through nested directories. Extension can be provided
        optionally. I should just make the recursion a command line flag, shouldn't I...
    """

    file_list = list()


    # Confirm file path exists
    print(f'Checking {search_path}')
    sleep(.2)
    if not os.path.exists(search_path):
        sys.exit('Specified path does not exist')
    elif not os.path.isdir(search_path):
        sys.exit('Path to directory required')
    else:
        print(f'Path found\nSearching for {ext}files')
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
