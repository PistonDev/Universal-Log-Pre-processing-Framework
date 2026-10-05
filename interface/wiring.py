from PySide6.QtCore import QTimer

from PySide6.QtWidgets import(
    QWidget,
    QVBoxLayout
)

from interface.models import *
from interface.gateway import Gateway
from interface.gui import App, MainWindow, CustomTaskBar, FileList, MessageBox

class UIWiring:
    def __init__(self, gateway: Gateway):
        self.gateway = Component(gateway)

        self.app = Component(App())
        self.window = Component(MainWindow("UPLF"))

        self.central_widget = QWidget()
        self.central_layout = QVBoxLayout(self.central_widget)

        self.taskbar = Component(CustomTaskBar(self.window.component))
        self.window.component.addToolBar(self.taskbar.component)

        self.file_list = Component(FileList(self.window.component))
        self.msgs_panel = Component(MessageBox())

        self.central_layout.addWidget(self.file_list.component)
        self.central_layout.addWidget(self.msgs_panel.component)

        self.window.component.setCentralWidget(self.central_widget)

        # connections
        self.network = NetworkManager()

        ## static
        self.connect_static()

        ## dynamic
        self.update_timer = QTimer()
        self.dynamic_timer = QTimer()

        self.dynamic_actions: set[int] = set()
        self.removal_actions: set[int] = set()

        self.dynamic_timer.timeout.connect(self.connect_dynamic)
        self.dynamic_timer.start(100)

        self.update_timer.timeout.connect(self.update)
        self.update_timer.start(100)

    def connect_static(self):
        self.select_button = self.taskbar.component.buttons["select"]

        # select button -> file list
        self.select_to_filelist: Connection = self.network.produce_connection(self.select_button.node, self.file_list.node, "select -> file list")

        self.select_button.component.instance.clicked.connect(lambda checked = False: self.network.transmit(
            self.select_to_filelist,
            self.select_button.component.event
        ))

        # process all button -> gateway
        self.process_all_button = self.taskbar.component.buttons["process_all"]
        self.process_all_button.component.event = Event(method = lambda: self.file_list.component.get_in_process_ids())

        self.process_to_gateway: Connection = self.network.produce_connection(self.process_all_button.node, self.gateway.node, "process all -> gateway")

        self.process_all_button.component.instance.clicked.connect(lambda checked = False: self.network.transmit(
            self.process_to_gateway,
            self.process_all_button.component.event
        ))

        # save all button -> gateway
        self.save_all_button = self.taskbar.component.buttons["save_all"]
        self.save_all_button.component.event = Event(method = lambda: self.file_list.component.get_in_save_ids())

        self.save_to_gateway: Connection = self.network.produce_connection(self.save_all_button.node, self.gateway.node, "save all -> gateway")

        self.save_all_button.component.instance.clicked.connect(lambda checked = False: self.network.transmit(
            self.save_to_gateway,
            self.save_all_button.component.event
        ))

    def connect_dynamic(self):

        # action button -> gateway
        for btn_id, btn_component in self.file_list.component.actions.items():

            if btn_component is None:
                continue

            if btn_id in self.dynamic_actions:
                if btn_id in self.file_list.component.actions_transition_queue:
                    self.file_list.component.actions_transition_queue.remove(btn_id)
                else:
                    continue

            conn: Connection = self.network.produce_connection(btn_component.node, self.gateway.node, "process -> gateway")

            btn_component.component.instance.clicked.connect(lambda checked = False, conn = conn, btn = btn_component: self.network.transmit(
                connection = conn,
                payload = btn.component.event
            ))

            self.dynamic_actions.add(btn_id)

        # removal button -> gateway
        for btn_id, btn_component in self.file_list.component.removal.items():

            if btn_component is None or btn_id in self.removal_actions:
                continue

            conn: Connection = self.network.produce_connection(btn_component.node, self.gateway.node, "removal -> gateway")

            btn_component.component.instance.clicked.connect(lambda checked = False, conn = conn, btn = btn_component: self.network.transmit(
                connection = conn,
                payload = btn.component.event
            ))

            self.removal_actions.add(btn_id)

    def update(self):
        self.file_list.component.extend_selected_files(self.file_list.node.terminal.eject())

        # gateway
        received: DataPacket = self.gateway.node.terminal.eject()

        if received:
            if received.rt_type == ReturnType.PROCESSING:
                fid = int(received.data)

                self.gateway.component.exec_file_pipeline(fid, self.file_list.component.files[fid])
                self.file_list.component.transition_action(fid)

            elif received.rt_type == ReturnType.REMOVING:
                fid = int(received.data)

                self.gateway.component.remove_from_file_pipeline(fid)
                self.file_list.component.reduce_rows(fid)

            elif received.rt_type == ReturnType.SAVING:
                fid = int(received.data)

                self.msgs_panel.component.add_message(self.gateway.component.save_file(fid))
                self.file_list.component.result_transition(fid)

            elif received.rt_type == ReturnType.PROCESS_ALL:
                if received.data:
                    for fid in received.data:
                        self.gateway.component.exec_file_pipeline(fid, self.file_list.component.files[fid])
                        self.file_list.component.transition_action(fid)

            elif received.rt_type == ReturnType.SAVE_ALL:
                if received.data:

                    for fid in received.data:
                        self.msgs_panel.component.add_message(self.gateway.component.save_file(fid))
                        self.file_list.component.result_transition(fid)

    def process(self):
        self.app.component.exec()

    def display(self):
        self.window.component.showMaximized()