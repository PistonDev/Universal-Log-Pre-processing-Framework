import os, sys, json
from dataclasses import asdict

class Serialize:

    @staticmethod
    def write(uv_events: list, file_name: str):
        output_dir = os.path.join(os.getcwd(), "output")
        write_path = os.path.join(output_dir, file_name + ".jsonl")

        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

        try:
            with open(file = write_path, mode = "w")as out_buffer:
                for event in uv_events:
                    data = asdict(event)

                    out_buffer.write(json.dumps(data, ensure_ascii = False) + "\n")

        except Exception as e:
            raise e