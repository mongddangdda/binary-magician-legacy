import os
import sys

sys.path.append(os.path.dirname(os.getcwd()))

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_all_files_from_path, get_matched_files_from_path


def get_func_refs(bv, func_name):
	symbol = bv.symbols[func_name]
	if len(symbol) > 1:
		for sym_type in symbol:
			if sym_type.type == SymbolType.ImportedFunctionSymbol:
				symbol = sym_type
				break
	refs = []
	for ref in bv.get_code_refs(symbol.address):
		refs.append((ref.function, ref.address))
	return refs

def solution(bv: BinaryViewType):
	dangerous_call = []
	# dangerous call
	# - printf
	# - fprintf
	# - vprintf, vfprintf, vsnprintf
	# - sprintf, snprintf
	printf_refs = get_func_refs(bv, 'printf')
	for function, addr in printf_refs:
		call_instr = function.get_low_level_il_at(addr).mlil
		#1. printf's param len == 1 and params is variable
		if len(call_instr.params) == 1 and \
			call_instr.params[0].operation == MediumLevelILOperation.MLIL_VAR:
			dangerous_call.append(function)
			print(function.name)
	#print(dangerous_call)
	return dangerous_call

if __name__ == '__main__':
	enterprise.connect()
	enterprise.authenticate_with_credentials("", "")
	with enterprise.LicenseCheckout():
		file_list = get_all_files_from_path(f'D:\\binja-snippets\\CWE134_Uncontrolled_Format_String\\s01\\only_printf')
		#runner = Runner(solution, file_list)
		#runner.run(cpp_only=True)
		for file_ in file_list:
			with open_view(file_) as bv:
				print('[+]', os.path.basename(file_))
				solution(bv)
				print('')
