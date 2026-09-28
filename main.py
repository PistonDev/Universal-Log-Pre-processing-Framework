import sys

from process.file_read import ProcessFile, ERROR_READ

class Main:
    def __init__(self):
        self.log_datas = []

    def set_data(self, data):
        self.log_datas.append(data)

    def display_logs(self):
        for log in self.log_datas:
            print("Log : \n" + log + "\n")

if __name__ == '__main__':

    main = Main()

    for arg in sys.argv[1:]:
        file = ProcessFile(arg)
        file.process()

        data = file.get_data()

        if (data == ERROR_READ):
            continue
        else:
            main.set_data(data)

    main.display_logs()