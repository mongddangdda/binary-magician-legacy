import angr
from utils.path.path_generator import PathObject
from utils.path.node import PEdge
import logging
from binaryninja import Function

class AngrManager():
    def __init__(self, path: PathObject) -> None:
        self.path = path
        self.binary = path.bv.file.filename
        self.project = angr.Project(self.binary, load_options={'main_opts': {'custom_base_addr': 0x0}}) # same load as binary ninja

    def make_find_address(self) -> list[int]:
        result = []
        
        source: PEdge = self.path.source
        result.append(source.address)

        for _, _, call_site in self.path.path:
            call_site: int
            result.append(call_site)

        sink: PEdge = self.path.sink
        result.append(sink.address)

        return result

    def check_feasible(self) -> bool:
        entry_state = self.project.factory.entry_state()
        simulation = self.project.factory.simgr(entry_state)

        find_address = self.make_find_address()

        simulation.explore(find=find_address)

        if simulation.found:
            logging.debug(f'This path are feasible!')
            return True
        else:
            logging.debug(f'This path are not feasible!')
            return False