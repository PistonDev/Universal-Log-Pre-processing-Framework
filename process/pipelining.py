from datetime import datetime
from dataclasses import dataclass

from parsers.parser import IParser, GenParser
from process.file_catg import DetectFile
from process.file_read import ProcessFile, ERROR_READ
from process.serialization import Serialize

@dataclass
class DataFormat:
    log_data:   str
    log_source: str
    parser:     IParser | None = None
    events:     list    | None = None

class Pipeline:
    def __init__(self):
        self.files_selected: dict[int, str] = {}
        self.files_processed: dict[int, tuple[str, list]] = {}

    def pipe_file(self, fid: int, file: str):
        self.files_selected[fid] = file

    def process_file(self):
        for fid, file in list(self.files_selected.items()):
            read_file: DataFormat = self.read_file(file)

            if read_file is None: 
                continue

            self.parse_file(read_file)

            normalized_val: tuple[str, list] = (read_file.log_source, self.normalize_file(read_file))

            self.files_processed[fid] = normalized_val
            self.files_selected.pop(fid)

    def save_and_return(self, fid: int) -> str | None:
        val: tuple[str, list] = self.files_processed[fid]

        if val:
            stamp: str = self.write_file(val[0], val[1])
            return stamp
        return None

    def read_file(self, file: str) -> DataFormat | None:
        pfile = ProcessFile(file)
        pfile.process()

        data = pfile.get_data()

        if data != ERROR_READ:
            detector = DetectFile(data)
            source = detector.detect()

            data_struct = DataFormat(
                log_data = data,
                log_source = source
            )

            return data_struct

    def parse_file(self, file: DataFormat):
        parser = GenParser(file.log_data, file.log_source).get_parser()
        events = parser.parse()

        file.parser = parser
        file.events = events

    def normalize_file(self, file: DataFormat) -> list:
        uv_events = []

        for event in file.events:
            uv_events.append(file.parser.normalize(event))

        return uv_events

    def write_file(self, source: str, uv_events: list) -> str:
        stamp: str = datetime.now().strftime("%Y-%m-%d_%Hh-%Mm-%Ss") + "_src_" + source

        Serialize().write(uv_events, stamp)
        return stamp