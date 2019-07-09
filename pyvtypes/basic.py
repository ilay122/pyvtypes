# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

""" This file defines some basic types which might be useful for many
OS's
"""
import struct, socket, datetime

import obj
import debug #pylint: disable-msg=W0611
import native_types
import utils
import encodings.utf_16

class String(obj.BaseObject):
	"""Class for dealing with Strings"""
	def __init__(self, theType, offset, vm = None, encoding = 'ascii',
				 length = 1, parent = None, profile = None, **kwargs):

		## Allow length to be a callable:
		if callable(length):
			length = length(parent)

		self.length = length
		self.encoding = encoding

		## length must be an integer
		obj.BaseObject.__init__(self, theType, offset, vm, parent = parent, profile = profile, **kwargs)

	def proxied(self, name): #pylint: disable-msg=W0613
		""" Return an object to be proxied """
		return self.__str__()

	def v(self):
		"""
		Use zread to help emulate reading null-terminated C
		strings across page boundaries.

		@returns: If all bytes are available, return the full string
		as a raw byte buffer. If the end of the string is in a page
		that isn't available, return as much of the string as possible,
		padded with nulls to the string's length.

		If the string length is 0, vtop() fails, or the physical addr
		of the string is not valid, return NoneObject.

		Note: to get a null terminated string, use the __str__ method.
		"""
		result = self.obj_vm.zread(self.obj_offset, self.length)
		if not result:
			return obj.NoneObject("Cannot read string length {0} at {1:#x}".format(self.length, self.obj_offset))
		return result

	def __len__(self):
		"""This returns the length of the string"""
		return len(unicode(self))

	def __str__(self):
		"""
		This function ensures that we always return a string from the __str__ method.
		Any unusual/unicode characters in the input are replaced with ?.

		Note: this effectively masks the NoneObject alert from .v()
		"""
		return unicode(self).encode('ascii', 'replace') or ""

	def __unicode__(self):
		""" This function returns the unicode encoding of the data retrieved by .v()
			Any unusual characters in the input are replaced with \ufffd.
		"""
		return self.v().decode(self.encoding, 'replace').split("\x00", 1)[0] or u''

	def __format__(self, formatspec):
		return format(self.__str__(), formatspec)

	def __cmp__(self, other):
		if str(self) == other:
			return 0
		return -1 if str(self) < other else 1

	def __add__(self, other):
		"""Set up mappings for concat"""
		return str(self) + other

	def __radd__(self, other):
		"""Set up mappings for reverse concat"""
		return other + str(self)

class Flags(obj.NativeType):
	""" This object decodes each flag into a string """
	## This dictionary maps each bit to a String
	bitmap = None

	## This dictionary maps a string mask name to a bit range
	## consisting of a list of start, width bits
	maskmap = None

	def __init__(self, theType = None, offset = 0, vm = None, parent = None,
				 bitmap = None, maskmap = None, target = "unsigned long",
				 **kwargs):
		self.bitmap = bitmap or {}
		self.maskmap = maskmap or {}
		self.target = target

		self.target_obj = obj.Object(target, offset = offset, vm = vm, parent = parent)
		obj.NativeType.__init__(self, theType, offset, vm, parent, **kwargs)

	def v(self):
		return self.target_obj.v()

	def __str__(self):
		result = []
		value = self.v()
		keys = self.bitmap.keys()
		keys.sort()
		for k in keys:
			if value & (1 << self.bitmap[k]):
				result.append(k)

		return ', '.join(result)

	def __format__(self, formatspec):
		return format(self.__str__(), formatspec)

	def __getattr__(self, attr):
		maprange = self.maskmap.get(attr)
		if not maprange:
			return obj.NoneObject("Mask {0} not known".format(attr))

		bits = 2 ** maprange[1] - 1
		mask = bits << maprange[0]

		return self.v() & mask

class IpAddress(obj.NativeType):
	"""Provides proper output for IpAddress objects"""

	def __init__(self, theType, offset, vm, **kwargs):
		obj.NativeType.__init__(self, theType, offset, vm, format_string = "4s", **kwargs)

	def v(self):
		return utils.inet_ntop(socket.AF_INET, obj.NativeType.v(self))

class Ipv6Address(obj.NativeType):
	"""Provides proper output for Ipv6Address objects"""
	def __init__(self, theType, offset, vm, **kwargs):
		obj.NativeType.__init__(self, theType, offset, vm, format_string = "16s", **kwargs)

	def v(self):
		return utils.inet_ntop(socket.AF_INET6, obj.NativeType.v(self))

class Enumeration(obj.NativeType):
	"""Enumeration class for handling multiple possible meanings for a single value"""

	def __init__(self, theType = None, offset = 0, vm = None, parent = None,
				 choices = None, target = "unsigned long", **kwargs):
		self.choices = choices or {}
		self.enum_name = kwargs.get("enum_name", "")
		self.enum_dict = {}
		if self.enum_name != "":
			self.enum_dict = vm.profile.enums[self.enum_name]
		self.target = target
		self.target_obj = obj.Object(target, offset = offset, vm = vm, parent = parent)
		obj.NativeType.__init__(self, theType, offset, vm, parent, **kwargs)

	def v(self):
		return self.target_obj.v()

	def __str__(self):
		value = self.v()
		if value in self.choices.keys():
			return self.choices[value]
		if value in self.enum_dict:
			return self.enum_dict[str(value)]
		return 'Unknown choice ' + str(value)

	def __format__(self, formatspec):
		return format(self.__str__(), formatspec)
	
	def __repr__(self):
		return " [{0};{2}]: {1}".format(self._vol_theType, self.v(), self.enum_name)


class VOLATILITY_MAGIC(obj.CType):
	"""Class representing a VOLATILITY_MAGIC namespace
	
	   Needed to ensure that the address space is not verified as valid for constants
	"""
	def __init__(self, theType, offset, vm, **kwargs):
		try:
			obj.CType.__init__(self, theType, offset, vm, **kwargs)
		except obj.InvalidOffsetError:
			# The exception will be raised before this point,
			# so we must finish off the CType's __init__ ourselves
			self.__initialized = True


class VolatilityMaxAddress(obj.VolatilityMagic):
	"""The maximum address of a profile's 
	underlying AS. 

	On x86 this is 0xFFFFFFFF (2 ** 32) - 1
	On x64 this is 0xFFFFFFFFFFFFFFFF (2 ** 64) - 1 

	We use a VolatilityMagic to calculate this 
	based on the size of an address, since that's 
	something we can already rely on being set
	properly for the AS. 
	"""

	def generate_suggestions(self):
		yield 2 ** (self.obj_vm.profile.get_obj_size("address") * 8) - 1


class _UNICODE_STRING(obj.CType):
	"""Class representing a _UNICODE_STRING

	Adds the following behavior:
	  * The Buffer attribute is presented as a Python string rather
		than a pointer to an unsigned short.
	  * The __str__ method returns the value of the Buffer.
	"""
	def v(self):
		"""
		If the claimed length of the string is acceptable, return a unicode string.
		Otherwise, return a NoneObject.
		"""
		data = self.dereference()
		if data:
			return unicode(data)
		return data

	def dereference(self):
		length = self.Length.v()
		if length > 0 and length <= 1024:
			data = self.Buffer.dereference_as('String', encoding = 'utf16', length = length)
			return data
		else:
			return obj.NoneObject("Buffer length {0} for _UNICODE_STRING not within bounds".format(length))

	def proxied(self, _name):
		return str(self)

	def __nonzero__(self):
		## Unicode strings are valid if they point at a valid memory
		return bool(self.Buffer and self.Length.v() > 0 and self.Length.v() <= 1024)

	def __format__(self, formatspec):
		return format(self.v(), formatspec)

	def __str__(self):
		return str(self.v().encode("utf8", "ignore"))

	def __unicode__(self):
		return unicode(self.dereference())

	def __len__(self):
		return len(self.dereference())

class _LIST_ENTRY(obj.CType):
	""" Adds iterators for _LIST_ENTRY types """
	def get_next_entry(self, member):
		return self.m(member).dereference()
	
	def list_of_type(self, type, member, forward = True, head_sentinel = True):
		if not self.is_valid():
			return

		## Get the first element
		if forward:
			nxt = self.get_next_entry("Flink")
		else:
			nxt = self.get_next_entry("Blink")

		offset = self.obj_vm.profile.get_obj_offset(type, member)

		seen = set()
		if head_sentinel:
			# We're a header element and not to be included in the list
			seen.add(self.obj_offset)

		while nxt.is_valid() and nxt.obj_offset not in seen:

			## Instantiate the object
			item = obj.Object(type, offset = nxt.obj_offset - offset,
									vm = self.obj_vm,
									parent = self.obj_parent,
									native_vm = self.obj_native_vm,
									name = type)

			seen.add(nxt.obj_offset)

			yield item

			if forward:
				nxt =  item.m(member).get_next_entry("Flink")
			else:
				nxt = item.m(member).get_next_entry("Blink")

	def __nonzero__(self):
		## List entries are valid when both Flinks and Blink are valid
		return bool(self.Flink) or bool(self.Blink)

	def __iter__(self):
		return self.list_of_type(self.obj_parent.obj_name, self.obj_name)


class BasicObjectClasses(obj.ProfileModification):

	def modification(self, profile):
		profile.object_classes.update({
			'String': String,
			'Flags': Flags,
			'Enumeration': Enumeration,
			'VOLATILITY_MAGIC': VOLATILITY_MAGIC,
			'VolatilityMaxAddress': VolatilityMaxAddress,
			'_UNICODE_STRING': _UNICODE_STRING,
			'_LIST_ENTRY': _LIST_ENTRY,
			'IpAddress': IpAddress,
			'Ipv6Address': Ipv6Address,
			})

		profile.merge_overlay({'VOLATILITY_MAGIC': [None, {
			'MaxAddress': [0x0, ['VolatilityMaxAddress']],
			}]})

### DEPRECATED FEATURES ###
#
# These are due from removal after version 2.2,
# please do not rely upon them

x86_native_types_32bit = native_types.x86_native_types
x86_native_types_64bit = native_types.x64_native_types



