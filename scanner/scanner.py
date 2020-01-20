import threading
import logging
import yara

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-9s %(message)s,')

class Scanner(threading.Thread):
    """
        Generate Scanner thread, which
        scans a given file for matches using provided
        yara ruleset.
    """

    def __init__(self, rule_set, file_to_scan):
        assert isinstance(rule_set, yara.Rules), 'Not yara rules'
        self.file = file_to_scan
        self.rules = rule_set
        super().__init__()

    def run(self):
        logging.debug(f'Scanning {self.file}')
        matches = self.rules.match(self.file)
        if matches:
            for match in matches:
                print(f'File: {self.file}\nDetected: {match}')



