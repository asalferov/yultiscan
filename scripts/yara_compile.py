import sys
import time
import yara

from yultiscan.scripts.utils import file_list_gen
from yultiscan.scanner import scanner


def compile_yars(rule_path, compile_path='.'):
    # Generate list of yara files
    rule_list = file_list_gen(rule_path, '.yar')
    all_rule_file = ''.join([compile_path, 'all_rules.yar'])

    with open(all_rule_file, 'wb') as all_rules:
        print(f'Creating combined rules file: {all_rules.name}')
        for yara_file in rule_list:
            with open(yara_file, 'rb') as file_to_write:
                buf = file_to_write.read()
                all_rules.write(buf)
        all_rules.seek(0)
        all_rules.close()

    print(f'Compiling {all_rule_file}')

    try:
        return yara.compile(filepath=all_rule_file, includes=False, error_on_warning=True)
    except yara.WarningError as err:
        sys.exit(f'[Compilation] Warning: {err}')
    except yara.SyntaxError as err:
        sys.exit(f'[Compilation] Syntax Error: {err}')
    except yara.Error as err:
        sys.exit(f'[Compilation] Error Occurred: {err}')


if __name__ == '__main__':
    # Default paths for testing
    rule_path = '/root/Documents/ransom/'
    compile_path = '/root/Documents/'
    scan_path = '/root/Documents/malware_samples/Ransomware.WannaCry/'
    # Compile rules into rules object
    rules = compile_yars(rule_path, compile_path)
    print('Ruleset compiled.')
    # Generate list of files to scan
    files_to_scan = file_list_gen(scan_path)
    print('Collected files to scan.')
    start = time.time()
    for file in files_to_scan:
        t = scanner.Scanner(rules, file)
        t.start()
        t.join()
    end = time.time()
    print(f'For-Loop Thread based approach: {end-start}')
    start = time.time()
    for file in files_to_scan:
        matches = rules.match(file)
        if matches:
            for match in matches:
                print(f'File: {file}\nDetected: {match}')
    end = time.time()
    print(f'Non-thread based approach: {end-start}')
