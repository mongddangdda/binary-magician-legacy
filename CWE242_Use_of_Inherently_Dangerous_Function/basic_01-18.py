from binaryninja import *

bv = binaryview.BinaryViewType.get_view_of_file('/Users/ch4rli3kop/binary-nomaj/test_workspace/CWE242_Use_of_Inherently_Dangerous_Function__basic_01.out')

targets = {
    'gets': [0],
    '_gets': [0]
}

result = [] # spicious function list

for target in targets:
    target = bv.get_functions_by_name(target)
    if len(target) < 1:
        continue
    target = target[0]
    xrefs = bv.get_code_refs(target.start)
    for ref in xrefs:
        text = f'suspicous point : {ref.address:#x} at function {ref.function.start:#x}'
        print(text)
        result.append(ref.function)

# evaluate results
# Todo: make listing bad function more clear (this case does not address *_badsink function)
# Todo: make comparing result with the real bad function more clear
import re
bad_functions = [func for func in bv.functions if re.match('_CWE.*_bad', func.name)]
for func in bad_functions:
    if func in result:
        result.pop()
    else:
        print(f'you cant detect the bad function at {func.start:#x}')

if len(result) > 0:
    for func in result:
        print(f'false positive at {func.start:#x}')
else:
    print(f'gooood')