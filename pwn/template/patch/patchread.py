import sys
import lief
from lief.ELF import *
from pwn import *

def code_to_str(ori):
	ans = ''
	while(ori):
		ans += chr(ori & 0xff)
		ori >>= 8
	ans = ans.ljust(4, '\x00')
	return ans

def patch_call(binary, start, target, arch):
	print('start', hex(start), 'target: ', hex(target))
	call_code = code_to_str((target - (start + 5)) & 0xffffffff)
	
	opcode = chr(0xe8) + call_code
	for code in call_code:
		print("code: ", ord(code))
	binary.patch_address(start, [ord(i) for i in opcode])

def bin_write(binary, target, opcode, arch):
	print(disasm(opcode, arch=arch))
	binary.patch_address(target, [i for i in opcode])

def write_to_frame():
	binary = lief.parse(sys.argv[1])
	with open(sys.argv[2], 'rb') as hook:
		frame_code = hook.read()

	frame_section = binary.get_section('.eh_frame')
	print("frmae_addr: ", frame_section.virtual_address)
	print("frame_flags: ", frame_section.flags)
	frame_section.flags |= 1


	bin_write(binary, frame_section.virtual_address, frame_code, 'amd64')
	patch_call(binary, 0x400594, frame_section.virtual_address, 'amd64')

	binary.write(sys.argv[1] + '_patch')

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print("Usage: <elf> <shellcode_bin>")
		sys.exit(1)
	write_to_frame()