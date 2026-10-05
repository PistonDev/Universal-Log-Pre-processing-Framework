from interface.gateway import Gateway
from interface.wiring import UIWiring
from process.pipelining import Pipeline

class Main:
    def __init__(self):
        self.pipeline = Pipeline()
        self.gateway = Gateway(self.pipeline)

    def get_gateway(self) -> Gateway:
        return self.gateway

class UI:
    def __init__(self, gateway: Gateway):
        self.wiring = UIWiring(gateway)

    def response(self):
        self.wiring.process()

    def display(self):
        self.wiring.display()

if __name__ == '__main__':
    main = Main()

    interface = UI(main.get_gateway())
    interface.display()
    interface.response()