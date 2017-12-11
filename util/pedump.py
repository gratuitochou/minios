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
		
		#COFF Fields
		self.Magic = struct.unpack("H", data[self.e_lfanew + 24:self.e_lfanew + 26])[0]
		self.MajorLinkerVersion = struct.unpack("B", data[self.e_lfanew + 26:self.e_lfanew + 27])[0]
		self.MinorLinkerVersion = struct.unpack("B", data[self.e_lfanew + 27:self.e_lfanew + 28])[0]
		self.SizeOfCode = struct.unpack("I", data[self.e_lfanew + 28:self.e_lfanew + 32])[0]
		self.SizeOfInitializedData = struct.unpack("I", data[self.e_lfanew + 32:self.e_lfanew + 36])[0]
		self.SizeOfUninitializedData = struct.unpack("I", data[self.e_lfanew + 36:self.e_lfanew + 40])[0]
		self.AddressOfEntryPoint = struct.unpack("I", data[self.e_lfanew + 40:self.e_lfanew + 44])[0]
		self.BaseOfCode = struct.unpack("I", data[self.e_lfanew + 44:self.e_lfanew + 48])[0]
		self.BaseOfData = struct.unpack("I", data[self.e_lfanew + 48:self.e_lfanew + 52])[0]
		
		#Windows Specific Fields
		self.ImageBase = struct.unpack("I", data[self.e_lfanew + 52:self.e_lfanew + 56])[0]
		self.SectionAlignment = struct.unpack("I", data[self.e_lfanew + 56:self.e_lfanew + 60])[0]
		self.FileAlignment = struct.unpack("I", data[self.e_lfanew + 60:self.e_lfanew + 64])[0]
		self.MajorOperatingSystemVersion = struct.unpack("H", data[self.e_lfanew + 64:self.e_lfanew + 66])[0]
		self.MinorOperatingSystemVersion = struct.unpack("H", data[self.e_lfanew + 66:self.e_lfanew + 68])[0]
		self.MajorImageVersion = struct.unpack("H", data[self.e_lfanew + 68:self.e_lfanew + 70])[0]
		self.MinorImageVersion = struct.unpack("H", data[self.e_lfanew + 70:self.e_lfanew + 72])[0]
		self.MajorSubsystemVersion = struct.unpack("H", data[self.e_lfanew + 72:self.e_lfanew + 74])[0]
		self.MinorSubsystemVersion = struct.unpack("H", data[self.e_lfanew + 74:self.e_lfanew + 76])[0]
		self.Win32VersionValue = struct.unpack("I", data[self.e_lfanew + 76:self.e_lfanew + 80])[0]
		self.SizeOfImage = struct.unpack("I", data[self.e_lfanew + 80:self.e_lfanew + 84])[0]
		self.SizeOfHeaders = struct.unpack("I", data[self.e_lfanew + 84:self.e_lfanew + 88])[0]
		self.CheckSum = struct.unpack("I", data[self.e_lfanew + 88:self.e_lfanew + 92])[0]
		self.Subsystem = struct.unpack("H", data[self.e_lfanew + 92:self.e_lfanew + 94])[0]
		self.DllCharacteristics = struct.unpack("H", data[self.e_lfanew + 94:self.e_lfanew + 96])[0]
		self.SizeOfStackReserve = struct.unpack("I", data[self.e_lfanew + 96:self.e_lfanew + 100])[0]
		self.SizeOfStackCommit = struct.unpack("I", data[self.e_lfanew + 100:self.e_lfanew + 104])[0]
		self.SizeOfHeapReserve = struct.unpack("I", data[self.e_lfanew + 104:self.e_lfanew + 108])[0]
		self.SizeOfHeapCommit = struct.unpack("I", data[self.e_lfanew + 108:self.e_lfanew + 112])[0]
		self.LoaderFlags = struct.unpack("I", data[self.e_lfanew + 112:self.e_lfanew + 116])[0]
		self.NumberOfRvaAndSizes = struct.unpack("I", data[self.e_lfanew + 116:self.e_lfanew + 120])[0]
		
		#Data Directory
		self.ExportTable = struct.unpack("I", data[self.e_lfanew + 120:self.e_lfanew + 124])[0]
		self.SizeOfExportTable = struct.unpack("I", data[self.e_lfanew + 124:self.e_lfanew + 128])[0]
		
		self.ImportTable = struct.unpack("I", data[self.e_lfanew + 128:self.e_lfanew + 132])[0]
		self.SizeOfImportTable = struct.unpack("I", data[self.e_lfanew + 132:self.e_lfanew + 136])[0]
		
		self.ResourceTable = struct.unpack("I", data[self.e_lfanew + 136:self.e_lfanew + 140])[0]
		self.SizeOfResourceTable = struct.unpack("I", data[self.e_lfanew + 140:self.e_lfanew + 144])[0]
		
		self.ExceptionTable = struct.unpack("I", data[self.e_lfanew + 144:self.e_lfanew + 148])[0]
		self.SizeOfExceptionTable = struct.unpack("I", data[self.e_lfanew + 148:self.e_lfanew + 152])[0]
		
		self.CertificateTable = struct.unpack("I", data[self.e_lfanew + 152:self.e_lfanew + 156])[0]
		self.SizeOfCertificateTable = struct.unpack("I", data[self.e_lfanew + 156:self.e_lfanew + 160])[0]
		
		self.BaseRelocationTable = struct.unpack("I", data[self.e_lfanew + 160:self.e_lfanew + 164])[0]
		self.SizeOfBaseRelocationTable = struct.unpack("I", data[self.e_lfanew + 164:self.e_lfanew + 168])[0]
		
		self.Debug = struct.unpack("I", data[self.e_lfanew + 168:self.e_lfanew + 172])[0]
		self.SizeOfDebug = struct.unpack("I", data[self.e_lfanew + 172:self.e_lfanew + 176])[0]
		
		self.ArchitectureData = struct.unpack("I", data[self.e_lfanew + 176:self.e_lfanew + 180])[0]
		self.SizeOfArchitectureData = struct.unpack("I", data[self.e_lfanew + 180:self.e_lfanew + 184])[0]
		
		self.GlobalPtr = struct.unpack("I", data[self.e_lfanew + 184:self.e_lfanew + 188])[0]
		self.SizeOfGlobalPtr = struct.unpack("I", data[self.e_lfanew + 188:self.e_lfanew + 192])[0]
		
		self.TLSTable = struct.unpack("I", data[self.e_lfanew + 192:self.e_lfanew + 196])[0]
		self.SizeOfTLSTable = struct.unpack("I", data[self.e_lfanew + 196:self.e_lfanew + 200])[0]
		
		self.LoadConfigTable = struct.unpack("I", data[self.e_lfanew + 200:self.e_lfanew + 204])[0]
		self.SizeOfLoadConfigTable = struct.unpack("I", data[self.e_lfanew + 204:self.e_lfanew + 208])[0]
		
		self.BoundImport = struct.unpack("I", data[self.e_lfanew + 208:self.e_lfanew + 212])[0]
		self.SizeOfBoundImoprt = struct.unpack("I", data[self.e_lfanew + 212:self.e_lfanew + 216])[0]
		
		self.ImportAddressTable = struct.unpack("I", data[self.e_lfanew + 216:self.e_lfanew + 220])[0]
		self.SizeOfImportAddressTable = struct.unpack("I", data[self.e_lfanew + 220:self.e_lfanew + 224])[0]
		
		self.DelayImportDescriptor = struct.unpack("I", data[self.e_lfanew + 224:self.e_lfanew + 228])[0]
		self.SizeOfDelayImportDescriptor = struct.unpack("I", data[self.e_lfanew + 228:self.e_lfanew + 232])[0]
		
		self.CLRRuntimeHeader = struct.unpack("I", data[self.e_lfanew + 232:self.e_lfanew + 236])[0]
		self.SizeOfCLRRuntimeHeader = struct.unpack("I", data[self.e_lfanew + 236:self.e_lfanew + 240])[0]
		
		self.Reserved = struct.unpack("I", data[self.e_lfanew + 240:self.e_lfanew + 244])[0]
		self.SizeOfReserved = struct.unpack("I", data[self.e_lfanew + 244:self.e_lfanew + 248])[0]
		
		self.sections = {}
		pos = self.e_lfanew + 248
		for _ in xrange(self.NumberOfSections):
			name = struct.unpack("8s", data[pos:pos + 8])[0]
			VirtualSize = struct.unpack("I", data[pos + 8:pos + 12])[0]
			VirtualAddress = struct.unpack("I", data[pos + 12:pos + 16])[0]
			SizeOfRawData = struct.unpack("I", data[pos + 16:pos + 20])[0]
			PointerToRawData = struct.unpack("I", data[pos + 20:pos + 24])[0]
			PointerToRelocations = struct.unpack("I", data[pos + 24:pos + 28])[0]
			PointerToLineNumbers = struct.unpack("I", data[pos + 28:pos + 32])[0]
			NumberOfRelocations = struct.unpack("H", data[pos + 32:pos + 34])[0]
			NumberOfLineNumbers = struct.unpack("H", data[pos + 34:pos + 36])[0]
			Characteristics = struct.unpack("I", data[pos + 36:pos + 40])[0]
			
			self.sections[name] = (name, VirtualSize, VirtualAddress, SizeOfRawData, 
								PointerToRawData, PointerToRelocations, PointerToLineNumbers,
								NumberOfRelocations, NumberOfLineNumbers, Characteristics)
			pos = pos + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 2 + 4
		
		
		

	def __repr__(self, *args, **kwargs):
		dos_header = DosHeader.__repr__(self, *args, **kwargs)
		pe_header = '''
		**** Pe Header ****
		Signature: 0x%08X
		Machine: 0x%04X
		NumberOfSections: 0x%04X
		TimeDataStamp: 0x%08X, %s
		PointerToSymbolTable: 0x%08X
		NumberOfSymbols: 0x%08X
		SizeOfOptionalHeader: 0x%04X
		Characteristics: 0x%04X
		
		Magic: 0x%04X
		MajorLinkerVersion: 0x%02X
		MinorLinkerVersion: 0x%02X
		SizeOfCode: 0x%08X
		SizeOfInitializedData: 0x%08X
		SizeOfUninitializedData: 0x%08X
		AddressOfEntryPoint: 0x%08X
		BaseOfCode: 0x%08X
		BaseOfData: 0x%08X
		ImageBase: 0x%08X
		SectionAlignment: 0x%08X
		FileAlignment: 0x%08X
		MajorOperatingSystemVersion: 0x%04X
		MinorOperatingSystemVersion: 0x%04X
		MajorImageVersion: 0x%04X
		MinorImageVersion: 0x%04X
		MajorSubsystemVersion: 0x%04X 
		MinorSubsystemVersion: 0x%04X 
		Win32VersionValue 0x%08X 
		SizeOfImage: 0x%08X 
		SizeOfHeaders: 0x%08X 
		CheckSum: 0x%08X 
		Subsystem: 0x%04X 
		DllCharacteristics: 0x%04X 
		SizeOfStackReserve: 0x%08X 
		SizeOfStackCommit: 0x%08X 
		SizeOfHeapReserve: 0x%08X 
		SizeOfHeapCommit: 0x%08X 
		LoaderFlags: 0x%08X 
		NumberOfRvaAndSizes: 0x%08X 
		
		#Data Directory
		ExportTable: 0x%08X, SizeOfExportTable: 0x%08X 
		ImportTable: 0x%08X, SizeOfImportTable: 0x%08X 
		ResourceTable: 0x%08X, SizeOfResourceTable: 0x%08X 
		ExceptionTable: 0x%08X, SizeOfExceptionTable: 0x%08X 
		CertificateTable: 0x%08X, SizeOfCertificateTable: 0x%08X 
		BaseRelocationTable: 0x%08X, SizeOfBaseRelocationTable: 0x%08X 
		Debug: 0x%08X, SizeOfDebug: 0x%08X 
		ArchitectureData: 0x%08X, SizeOfArchitectureData: 0x%08X 
		GlobalPtr: 0x%08X, SizeOfGlobalPtr: 0x%08X 
		TLSTable: 0x%08X, SizeOfTLSTable: 0x%08X 
		LoadConfigTable: 0x%08X, SizeOfLoadConfigTable: 0x%08X 
		BoundImport: 0x%08X, SizeOfBoundImoprt: 0x%08X 
		ImportAddressTable: 0x%08X, SizeOfImportAddressTable: 0x%08X 
		DelayImportDescriptor: 0x%08X, SizeOfDelayImportDescriptor: 0x%08X 
		CLRRuntimeHeader: 0x%08X, SizeOfCLRRuntimeHeader: 0x%08X 
		Reserved: 0x%08X, SizeOfReserved: 0x%08X 
		''' % (
			self.Signature, self.Machine, self.NumberOfSections, self.TimeDateStamp, time.ctime(self.TimeDateStamp),
			self.PointerToSymbolTable, self.NumberOfSymbols, self.SizeOfOptionalHeader, self.Characteristics,
			
			#COFF Fields
			self.Magic,	self.MajorLinkerVersion, self.MinorLinkerVersion, self.SizeOfCode,
			self.SizeOfInitializedData, 	self.SizeOfUninitializedData, self.AddressOfEntryPoint ,
			self.BaseOfCode, self.BaseOfData ,
			
			#Windows Specific Fields
			self.ImageBase, 	self.SectionAlignment, self.FileAlignment, self.MajorOperatingSystemVersion ,
			self.MinorOperatingSystemVersion, self.MajorImageVersion, self.MinorImageVersion,
			self.MajorSubsystemVersion, 	self.MinorSubsystemVersion, self.Win32VersionValue,
			self.SizeOfImage, self.SizeOfHeaders, self.CheckSum, self.Subsystem, self.DllCharacteristics ,
			self.SizeOfStackReserve, self.SizeOfStackCommit, self.SizeOfHeapReserve,
			self.SizeOfHeapCommit, self.LoaderFlags, self.NumberOfRvaAndSizes,
			
			#Data Directory
			self.ExportTable, self.SizeOfExportTable,
			self.ImportTable, self.SizeOfImportTable,
			self.ResourceTable, 	self.SizeOfResourceTable,
			self.ExceptionTable, self.SizeOfExceptionTable,
			self.CertificateTable, self.SizeOfCertificateTable,
			self.BaseRelocationTable, self.SizeOfBaseRelocationTable,
			self.Debug, 	self.SizeOfDebug,
			self.ArchitectureData, self.SizeOfArchitectureData,
			self.GlobalPtr,	self.SizeOfGlobalPtr,
			self.TLSTable, self.SizeOfTLSTable,
			self.LoadConfigTable, self.SizeOfLoadConfigTable,
			self.BoundImport, self.SizeOfBoundImoprt,
			self.ImportAddressTable, self.SizeOfImportAddressTable,
			self.DelayImportDescriptor, 	self.SizeOfDelayImportDescriptor,
			self.CLRRuntimeHeader, self.SizeOfCLRRuntimeHeader,
			self.Reserved, self.SizeOfReserved
			)
		
		sections = "#sections blow, total: %d\n" % (self.NumberOfSections)
		for val in self.sections.values():
			sections  += '''
		name: %s
		VirtualSize: 0x%08X
		VirtualAddress: 0x%08X
		SizeOfRawData 0x%08X
		PointerToRawData: 0x%08X
		PointerToRelocations: 0x%08X
		PointerToLineNumbers: 0x%08X
		NumberOfRelocations: 0x%04X
		NumberOfLineNumbers: 0x%04X
		Characteristics: 0x%08X
			'''%(val[0], val[1], val[2], val[3], val[4], val[5],
				val[6], val[7], val[8], val[9]
				)
		
		return dos_header + pe_header + sections



#test
if __name__ == "__main__":
	fp = "winpe.exe"
	with open(fp, "rb") as f:
		obj = PeHeader(f.read())
	print obj








