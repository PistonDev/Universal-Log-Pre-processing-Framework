import os

from collections import deque
from PySide6.QtCore import Qt

from PySide6.QtWidgets import (
    QToolBar,
    QHeaderView,
    QMainWindow,  
    QPushButton,
    QFileDialog,
    QApplication, 
    QTableWidget,
    QTableWidgetItem
    )

from interface.models import *

class App(QApplication):
    def __init__(self):
        super().__init__([])

class MainWindow(QMainWindow):
    def __init__(self, title: str):
        super().__init__()

        self.setWindowTitle(title)

class CustomTaskBar(QToolBar):
    def __init__(self, parent: MainWindow):
        super().__init__()

        self.buttons = {
            "select": 
                Component(
                    Button(event = Event(method = lambda parent = self: open_files(parent)), instance = QPushButton("Select"))
                ),

            "process_all":
                Component(
                    Button(event = Event(), instance = QPushButton("Process All"))
                )
        }

        for button in self.buttons.values():
            self.addWidget(button.component.instance)

class FileList(QTableWidget):
    def __init__(self, parent: MainWindow):
        super().__init__(0, 3, parent)

        self.setHorizontalHeaderLabels(["files", "actions", "remove"])
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)

        self.next_id = 0
        self.row_by_id: dict[int, int] = {}

        self.files: dict[int, str] = {}
        self.actions: dict[int, Component: Button | None] = {}
        self.removal: dict[int, Component: Button | None] = {}

        self.actions_transition_queue = deque()

    def get_in_process_ids(self) -> DataPacket:
        process_ids = []

        for fid, comp in self.actions.items():
            btn: Component[Button] = comp

            if btn.component.bt_type == ButtonType.PROCESS:
                process_ids.append(fid)

        return to_packet(process_ids, ReturnType.PROCESS_ALL)

    def extend_selected_files(self, packet: DataPacket):
        if packet is not None:

            for file in packet.data:       
                file_id = self.next_id
                self.next_id += 1

                self.files[file_id] = file
                self.enumerate_rows(file_id)

    def enumerate_rows(self, fid: int):
        row = self.rowCount()
        self.insertRow(row)

        self.row_by_id[fid] = row

        # file
        item = QTableWidgetItem(self.files[fid])
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.setItem(row, 0, item)

        # button
        button = Component(
            Button(
                event = Event(method = lambda id = fid: to_packet(id, ReturnType.PROCESSING)),
                instance = QPushButton("Process"),
                bt_type = ButtonType.PROCESS
            )
        )
        self.setCellWidget(row, 1, button.component.instance)
        self.actions[fid] = button

        button = Component(
            Button(
                event = Event(method = lambda id = fid: to_packet(id, ReturnType.REMOVING)),
                instance = QPushButton("Remove"),
                bt_type = ButtonType.REMOVE
            )
        )
        self.setCellWidget(row, 2, button.component.instance)
        self.removal[fid] = button

    def transition_action(self, id: int):
        btn_component: Component[Button] = self.actions[id]
        btn = btn_component.component

        btn.instance.setText("Save")
        btn.event = Event(
            method = lambda id = id: to_packet(id, ReturnType.SAVING)
        )
        btn.bt_type = ButtonType.SAVE

        self.actions_transition_queue.append(id)

    def result_transition(self, fid: int):
        row = self.row_by_id[fid]

        self.actions[fid] = None
        self.removal[fid] = None

        self.removeCellWidget(row, 1)
        self.removeCellWidget(row, 2)

        item = QTableWidgetItem("Saved")
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

        self.setItem(row, 1, item)
        self.setSpan(row, 1, 1, 2)

    def reduce_rows(self, fid: int):
        self.actions[fid] = None
        self.removal[fid] = None

        row = self.row_by_id[fid]
        self.removeRow(row)

        for other_id, other_row in self.row_by_id.items():
            if other_row > row:
                self.row_by_id[other_id] -= 1

def open_files(parent) -> DataPacket:
    return to_packet(QFileDialog.getOpenFileNames(
        parent,
        "Select Log Files",
        os.getcwd(),
        "log Files (*.txt, *.log);;All Files (*)"
    )[0], ReturnType.SELECTED)

def to_packet(data: Any, rt_type: ReturnType):
    return DataPacket(
        data = data,
        rt_type = rt_type
    )