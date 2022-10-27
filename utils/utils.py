import os
import re

from binaryninja.binaryview import BinaryViewType


def get_all_files_from_path(path: str, file_type: str = '.out') -> list[str]:
    file_list = []
    for root, _, files in os.walk(path):
        file_list = [os.path.join(root,file) for file in files if file.endswith(file_type)]
    return file_list

def get_matched_files_from_path(path, file_type='.out'):
    raise NotImplemented

def is_cpp_binary(bv: BinaryViewType) -> bool:
    
    for func in bv.functions:
        if func.name[:2] == '_Z':
            return True
    
    return False
