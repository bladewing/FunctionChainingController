"""
Interface for the SDN Controller
Implements means to communicate with the SDN Controller that supports REST API!
"""
from abc import abstractmethod, ABC


class ISDNController(ABC):
    def __init__(self):
        super(ISDNController, self).__init__()

    @abstractmethod
    def build_topology(self):
        raise NotImplementedError

    @abstractmethod
    def mod_chain(self, chainList):
        raise NotImplementedError

    @abstractmethod
    def update_manager(self, sec_app_manager):
        raise NotImplementedError