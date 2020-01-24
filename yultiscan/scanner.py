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
        """
       Pretty much does the whole thing in one go. Creates queue and
       utilizes own scan method as the worker function for each thread.
       Blocks until done, and exits. Not sure if too hacky to do all this
        within the constructor, though?

        :param rule_set: Compiled yara rules object to match against
        :param files_to_scan: list of files to scan for matches
        :param num_threads: number of threads to utilize
        """
        assert isinstance(rule_set, yara.Rules), 'Not yara rules'
        self.rules = rule_set
        self.threads = num_threads
        self.files = files_to_scan


    def run(self):
        """
       Pretty much does the whole thing in one go. Creates queue and
       utilizes own scan method as the worker function for each thread.
       Blocks until done, and exits.

        :return: None
        """
        # Generate queue object
        file_queue = queue.Queue(maxsize=200)
        # Initialize threads
        for i in range(self.threads):
            worker = threading.Thread(target=self.__scan__, args=(file_queue,))
            worker.setDaemon(True)
            worker.start()
        # Feed target files into queue to be processed
        for file in self.files:
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




