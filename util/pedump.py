#coding=utf8
'''
---------------------------
0x4D | 0x5A |
			Dos Header
			Dos Stub 
---------------------------
			PE Header
			
'''

import time
import struct
import binascii

class DosHeader(object):
	def __init__(self, data):
		super(DosHeader, self).__init__()
		
		self.e_magic = struct.unpack("H", data[:2])[0]
		self.e_cblp = struct.unpack("H", data[2:4])[0]
		self.e_cp = struct.unpack("H", data[4:6])[0]
		self.e_crlc = struct.unpack("H", data[6:8])[0]
		self.e_cparhdr = struct.unpack("H", data[8:10])[0]
		self.e_minalloc = struct.unpack("H", data[10:12])[0]
		self.e_maxalloc = struct.unpack("H", data[12:14])[0]
		self.e_ss = struct.unpack("H", data[14:16])[0]
		self.e_sp = struct.unpack("H", data[16:18])[0]
		self.e_csum = struct.unpack("H", data[18:20])[0]
		self.e_ip = struct.unpack("H", data[20:22])[0]
		self.e_cs = struct.unpack("H", data[22:24])[0]
		self.e_lfarlc = struct.unpack("H", data[24:26])[0]
		self.e_ovno = struct.unpack("H", data[26:28])[0]
		self.e_res = struct.unpack("Q", data[28:36])[0]
		self.e_oemid = struct.unpack("H", data[36:38])[0]
		self.e_oeminfo = struct.unpack("H", data[38:40])[0]
		self.e_res2 = data[40:60]
		self.e_lfanew = struct.unpack("I", data[60:64])[0]
		
	
	
	def __repr__(self, *args, **kwargs):
		return '''
		**** Dos Header ****
		e_magic: 0x%04X
		e_cblp: 0x%04X
		e_cp: 0x%04X
		e_crlc: 0x%04X
		e_cparhdr: 0x%04X
		e_minialloc: 0x%04X
		e_maxalloc: 0x%04X
		e_ss: 0x%04X
		e_sp: 0x%04X
		e_csum: 0x%04X
		e_ip: 0x%04X
		e_cs: 0x%04X
		e_lfarlc: 0x%04X
		e_ovno: 0x%04X
		e_res: 0x%016X
		e_oemid: 0x%04X
		e_oeminfo: 0x%04X
		e_res2: 0x%s
		e_lfanew: 0x%08X
		''' %(self.e_magic, self.e_cblp, self.e_cp, self.e_crlc, self.e_cparhdr, 
			self.e_minalloc, self.e_maxalloc, self.e_ss, self.e_sp, self.e_csum,
			self.e_ip, self.e_cs, self.e_lfarlc, self.e_ovno, self.e_res, self.e_oemid,
			self.e_oeminfo, binascii.hexlify(self.e_res2), self.e_lfanew)



class PeHeader(DosHeader):
	def __init__(self, data):
		super(PeHeader, self).__init__(data)
		
		#COFF Header
		self.Signature = struct.unpack("I", data[self.e_lfanew:self.e_lfanew + 4])[0]
		self.Machine = struct.unpack("H", data[self.e_lfanew + 4:self.e_lfanew + 6])[0]
		self.NumberOfSections = struct.unpack("H", data[self.e_lfanew + 6:self.e_lfanew + 8])[0]
		self.TimeDateStamp = struct.unpack("I", data[self.e_lfanew + 8:self.e_lfanew + 12])[0]
		self.PointerToSymbolTable = struct.unpack("I", data[self.e_lfanew + 12:self.e_lfanew + 16])[0]
		self.NumberOfSymbols = struct.unpack("I", data[self.e_lfanew + 16:self.e_lfanew + 20])[0]
		self.SizeOfOptionalHeader = struct.unpack("H", data[self.e_lfanew + 20:self.e_lfanew + 22])[0]
		self.Characteristics = struct.unpack("H", data[self.e_lfanew + 22:self.e_lfanew + 24])[0]


	def __repr__(self, *args, **kwargs):
		dos_header = DosHeader.__repr__(self, *args, **kwargs)
		return dos_header + '''
		**** Pe Header ****
		Signature: 0x%08X
		Machine: 0x%04X
		NumberOfSections: 0x%04X
		TimeDataStamp: 0x%08X, %s
		PointerToSymbolTable: 0x%08X
		NumberOfSymbols: 0x%08X
		SizeOfOptionalHeader: 0x%04X
		Characteristics: 0x%04X
		''' % (
			self.Signature, self.Machine, self.NumberOfSections, self.TimeDateStamp, time.ctime(self.TimeDateStamp),
			self.PointerToSymbolTable, self.NumberOfSymbols, self.SizeOfOptionalHeader, self.Characteristics
			)



#test
if __name__ == "__main__":
	fp = "winpe.exe"
	with open(fp, "rb") as f:
		obj = PeHeader(f.read())
	print obj








