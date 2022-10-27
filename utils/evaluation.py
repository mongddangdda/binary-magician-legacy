import os
import re

def get_all_files_from_path(path, file_type='.out'):
    file_list = []
    for root, _, files in os.walk(path):
        file_list = [os.path.join(root,file) for file in files if file.endswith(file_type)]
    return file_list

def get_answer(bv) -> list:
    # Todo: make listing bad function more clear (this case does not address *_badsink function)
    bad_functions = [func for func in bv.functions if re.match('_CWE.*_bad', func.name)]
    return bad_functions

def evaluate_result(result, answer):
    # evaluate results
    # Todo: make comparing result with the real bad function more clear (ex. calculate f1-score?)
    good = True
    for func in answer:
        if func in result:
            result.remove(func)
        else:
            print(f'[{func.view.file.filename}] : you cant detect the bad function at {func.start:#x}')
            good = False

    if len(result) > 0:
        for func in result:
            print(f'[{func.view.file.filename}] : false positive at {func.start:#x}')
            good = False
    if good:
        print(f'[{func.view.file.filename}] : good!')
