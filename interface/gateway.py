from process.pipelining import Pipeline

class Gateway:
    def __init__(self, file_pipeline: Pipeline):
        self.file_pipeline = file_pipeline

    def exec_file_pipeline(self, id: int, file: str):
        self.file_pipeline.pipe_file(id, file)
        self.file_pipeline.process_file()

    def remove_from_file_pipeline(self, id: int):
        if id in self.file_pipeline.files_selected:
            del self.file_pipeline.files_selected[id]

        if id in self.file_pipeline.files_processed:
            del self.file_pipeline.files_processed[id]

    def save_file(self, id: int) -> str:
        if id in self.file_pipeline.files_processed:

            stamp = self.file_pipeline.save_and_return(id)
            if stamp:
                return f" file saved at : {stamp}"
            
            raise ValueError("Save failed")