import threading
import logging
import queue
import yara

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-9s %(message)s,')


class Scanner:
    """
        Generates queue of files to scan for matches,
        and assigns worker threads to each file as they become
        available. Worker threads scan for matches with given ruleset.
    """

    def __init__(self, rule_set, files_to_scan, num_threads):
        assert isinstance(rule_set, yara.Rules), 'Not yara rules'
        self.rules = rule_set
        # Generate queue object
        file_queue = queue.Queue(maxsize=0)
        # Initialize threads
        for i in range(num_threads):
            worker = threading.Thread(target=self.__scan__, args=(file_queue,))
            worker.setDaemon(True)
            worker.start()
        # Feed target files into queue to be processed
        for file in files_to_scan:
            file_queue.put(file)
        # Block until all queue files have been processed
        file_queue.join()

    def __scan__(self, q):
        while True:
            current_file = q.get()
            logging.debug(f'Scanning {current_file}')
            matches = self.rules.match(current_file)
            if matches:
                for match in matches:
                    logging.debug(f'File: {current_file}\nDetected: {match}')
            q.task_done()
