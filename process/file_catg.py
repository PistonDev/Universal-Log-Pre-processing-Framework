import re

reg_expressions = {
    "apache" : r"^\[.*\] \[(notice|error|warn|info|debug)\]",
    "syslog" : r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"
}

class DetectFile:
    def __init__(self, data: str):
        self.data = data

    def detect(self) -> str:
        lines = self.data.splitlines()

        for line in lines:

            for source in reg_expressions:
                if re.match(reg_expressions[source], line):
                    return source

        return ""