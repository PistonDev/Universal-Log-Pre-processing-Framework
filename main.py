import sys

from pipeline.pipelining import Pipeline

class Main:
    def __init__(self):
        self.pipeline = Pipeline(sys.argv[1:])

    def process(self):
        self.pipeline.read_src(debug = False)
        self.pipeline.parse_src(debug = False)
        self.pipeline.normalize_src(debug = True)

if __name__ == '__main__':
    main = Main()
    main.process()