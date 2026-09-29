from dataclasses import dataclass

from parsers.parser import IParser, GenParser
from process.file_catg import DetectFile
from process.file_read import ProcessFile, ERROR_READ

@dataclass
class DataFormat:
    log_data:   str
    log_source: str
    parser:     IParser | None = None
    events:     list    | None = None

class Pipeline:
    def __init__(self, args):
        self.files = []

        self.structs = {}
        self.normalised_events = {}

        for arg in args:
            self.files.append(ProcessFile(arg))

    def read_src(self, debug):
        for i in range(len(self.files)):
            file = self.files[i]
            file.process()

            data = file.get_data()

            if data != ERROR_READ:

                # detect log file type
                detector = DetectFile(data)
                source = detector.detect()

                data_struct = DataFormat(
                    log_data = data,
                    log_source = source
                )

                self.structs[i] = data_struct

                if debug:
                    print(f"file {i} : source : {source}")

    def parse_src(self, debug):
        for _, struct in self.structs.items():
            parser = GenParser(struct.log_data, struct.log_source).get_parser()
            events = parser.parse()

            struct.parser = parser
            struct.events = events

            if debug:
                print([field for field in events])

    def normalize_src(self, debug):
        for id, struct in self.structs.items():
            uv_events = []

            for event in struct.events:
                uv_events.append(struct.parser.normalize(event))

            if debug:
                print([event for event in uv_events])

            self.normalised_events[id] = uv_events