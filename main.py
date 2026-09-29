import sys

from pipeline.pipelining import Pipeline

class Main:
    def __init__(self):
        self.pipeline = Pipeline(sys.argv[1:])

    def process(self, debug = False):
        self.pipeline.read_src(debug)
        self.pipeline.parse_src(debug)

if __name__ == '__main__':
    main = Main()
    main.process(debug = True)