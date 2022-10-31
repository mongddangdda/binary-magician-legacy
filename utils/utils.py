import re
from pathlib import Path
from binaryninja.binaryview import BinaryViewType


def get_all_files_from_path(path: str, depth_level: int = None, file_type: str = '.out') -> list[Path]:

    base_directory = Path(path)
    pattern = '**/*' # this means visiting all subdirectories recursively

    if depth_level is not None:
        pattern = '/'.join('*' * depth_level)

    file_list = [file for file in base_directory.glob(pattern) if file.is_file() and not file.name.startswith('.') and file.name.endswith(file_type)]
    return file_list

def get_matched_files_from_path(path: str, reg: str = '.*', depth_level: int = None, file_type: str = '.out') -> list[Path]:
    file_list = get_all_files_from_path(path, depth_level, file_type)
    n_file_list = [file for file in file_list if re.match(reg, file.name)]
    return n_file_list

def is_cpp_binary(bv: BinaryViewType) -> bool:
    
    for func in bv.functions:
        if func.name[:2] == '_Z':
            return True
    
    return False
