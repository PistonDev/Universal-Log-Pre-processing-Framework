from process.file_read import ProcessFile, ERROR_READ
from process.file_catg import DetectFile

class Pipeline:
    def __init__(self, args):
        self.files = []

        self.logs = {}
        self.events = {}

        for arg in args:
            self.files.append(ProcessFile(arg))

    def read_src(self, debug):
        for i in range(len(self.files)):
            file = self.files[i]
            file.process()

            data = file.get_data()

            if data != ERROR_READ:
                self.logs[i] = data

                detector = DetectFile(data)
                source = detector.detect()

                if debug:
                    print(f"file {i} : source : {source}")