import pyvtypes.obj as obj
import pyvtypes.obj_utils

import windows
import sys


class win_10_test_modification(obj.ProfileModification):
	conditions = {'os': lambda x: x == 'windows',
				  'major': lambda x: x == 6,
				  'minor': lambda x: x == 4}

	def modification(self, profile):

		metadata = profile.metadata
		build = metadata.get("build", 0)
		print "in the modification of:", self.__class__

class win_10_invalid_modification(obj.ProfileModification):
	conditions = {'os': lambda x: x == 'LINUX',
				  'major': lambda x: x == 6,
				  'minor': lambda x: x == 4}

	def modification(self, profile):

		metadata = profile.metadata
		build = metadata.get("build", 0)
		print "in the modification of:", self.__class__



class Win10x64_15063(obj.Profile):
	""" A Profile for Windows 10 x64 (10.0.15063.0 / 2017-04-04) with vtypes of win7 x64 service pack 0"""
	_md_memory_model = '64bit'
	_md_os = 'windows'
	_md_major = 6
	_md_minor = 4
	_md_build = 15063
	_md_vtype_module = 'win7_sp0_x64_vtypes'
	_md_product = ["NtProductWinNt"]
	

class my_address_space(pyvtypes.obj_utils.BaseAddressSpace):
	def __init__(self, pid, *args, **kwargs):
		pyvtypes.obj_utils.BaseAddressSpace.__init__(self, *args, **kwargs)
		self.proc = windows.winobject.process.WinProcess(pid=pid)
	
	def read(self, addr, size):
		return self.proc.read_memory(addr, size)
	
	def zread(self, offset, amount):
		real_got = self.read(offset, amount)
		to_ret = real_got + "\x00" * (amount - len(real_got)) # TODO: add cache to NULL bytes?
		return to_ret


def main():
	proc = windows.winobject.process.WinProcess(pid=int(sys.argv[1]))
	
	
	
	# addrspace = pyvtypes.obj_utils.get_vm_for_params(64, 'win7_sp0_x64_vtypes', read_function=proc.read_memory)
	my_addrspace = my_address_space(int(sys.argv[1]))
	addrspace = pyvtypes.obj_utils.get_vm_for_profile_and_addrspace(Win10x64_15063, my_addrspace)
	
	print addrspace
	peb = obj.Object("_PEB", offset=proc.peb_addr, vm=addrspace)
	print "OSBuildNumber:", peb.OSBuildNumber, ", BeingDebugged:", peb.BeingDebugged
	

if __name__ == "__main__":
	main()
	