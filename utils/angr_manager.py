from angr import *
from utils.path.path_generator import PathObject

class AngrManager():
    def __init__(self, path: PathObject) -> None:
        pass

'''
from angrutils import *
proj = angr.Project("testcase/a",load_options={'auto_load_libs': False})
main = proj.loader.main_object.get_symbol("main")
'''