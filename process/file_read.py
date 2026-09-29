import sys, json, os

ERROR_READ = ""

@staticmethod
def read_file(file_path) -> str:
    try:
        with open(file = file_path, mode = "r") as inp_buffer:
            data = inp_buffer.read()

            if (len(data) > 0):
                return data
            else:
                return ERROR_READ
            
    except FileNotFoundError:
        print(f"Given file name {file_path} is invalid!")
        sys.exit()

@staticmethod
def read_pattern(json_file) -> dict:
    json_path = os.path.join(os.getcwd(), "patterns", json_file + ".json")

    try:
        with open(file = json_path, mode = "r") as inp_buffer:
            data = json.load(inp_buffer)
            return data["patterns"]
        
    except FileNotFoundError:
        print(f"Given file name {json_path} is invalid!")
        sys.exit()

class ProcessFile:
    def __init__(self, file_path):
        self.file_path = file_path
        self.read_data = ERROR_READ

    def process(self):
        self.read_data = read_file(self.file_path)

    def get_data(self):
        return self.read_data