import obj

class BaseAddressSpace(object):
	"""
	my base address space - when creating a custom one, one should implement ALL of this in some way; based on volatility
	
	write is not mandatory
	"""
	def __init__(self, *args, **kwargs):
		pass

	def is_valid_address(self, addr):
		return True
		
	def read(self, addr, length):
		return None
		
	def zread(self, addr, length):
		return None

	def write(self, addr, data):
		return True


def get_vm_for_params(bitness, module_name, read_function=None, write_function=None, is_valid_function=None, more_metadata=None):
	class dummy_class(obj.Profile):
		pass
	
	# dummy_functions = ["is_valid_address", "write", "read"]
	
	class dummy_vm(object):
		def is_valid_address(self, offset):
			if is_valid_function != None:
				return is_valid_function(offset)
			return True
		
		def write(self, offset, data):
			if write_function != None:
				return write_function(offset, data)
			return True
		
		def read(self, offset, amount):
			if read_function != None:
				return read_function(offset, amount)
			return None
		def zread(self, offset, amount):
			real_got = self.read(offset, amount)
			to_ret = real_got + "\x00" * (amount - len(real_got)) # TODO: add cache to NULL bytes?
			return to_ret
	
	dummy_profile = dummy_class()
	dummy_profile.my_metadata = {}
	dummy_profile.my_metadata["vtype_module"] = module_name
	dummy_profile.my_metadata["memory_model"] = str(bitness) + "bit"
	
	if more_metadata == None:
		more_metadata = {}
	
	for key in more_metadata:
		dummy_profile.my_metadata[key] = more_metadata[key]
	
	dummy_profile.reset()
	
	vm_to_ret = dummy_vm()
	setattr(vm_to_ret, "profile", dummy_profile)
	
	return vm_to_ret


def get_vm_for_profile_and_addrspace(prof_type, addrspace):
	profile = prof_type()
	profile.reset()
	
	setattr(addrspace, "profile", profile)
	
	return addrspace
	