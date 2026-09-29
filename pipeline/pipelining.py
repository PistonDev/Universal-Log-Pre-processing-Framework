from parsers.parser import GenParser
from process.file_catg import DetectFile
from process.file_read import ProcessFile, ERROR_READ

class Pipeline:
    def __init__(self, args):
        self.files = []

        self.logs = {}
        self.events = {}
        self.sources = {}

        for arg in args:
            self.files.append(ProcessFile(arg))

    def read_src(self, debug):
        for i in range(len(self.files)):
            file = self.files[i]
            file.process()

            data = file.get_data()

            if data != ERROR_READ:

                # appending data
                self.logs[i] = data

                detector = DetectFile(data)
                source = detector.detect()

                # appending source
                self.sources[i] = source
                
                if debug:
                    print(f"file {i} : source : {source}")

    def parse_src(self, debug):
        for l_id, l_data in self.logs.items():
            events = GenParser(l_data, self.sources[l_id]).get_parser().parse()
            self.events[l_id] = events

            if debug:
                print([field for field in events])