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
	binary.patch_address(target, [ord(i) for i in opcode])

def write_to_frame():
	binary = lief.parse(sys.argv[1])
	call_addr = int(sys.argv[2], 16)

	frame_section = binary.get_section('.eh_frame')
	print("frame_addr: ", frame_section.virtual_address)
	print("frame_flags: ", frame_section.flags)
	frame_section.flags |= 1

	malloc_plt_list = binary.get_content_from_virtual_address(call_addr+1, 4)
	malloc_plt = 0 
	for i in malloc_plt_list[::-1]:
		malloc_plt = (malloc_plt << 8) + i
	malloc_plt = ((malloc_plt) + (call_addr+5)) & 0xffffffff
	print('malloc_plt, ', hex(malloc_plt))

	frame_code = '\xbf\x10\x00\x00\x00'				#mov edi, 0x10
	frame_code += '\xe8'							#call malloc@plt
	call_malloc = code_to_str((malloc_plt - (frame_section.virtual_address+10)) & 0xffffffff)
	frame_code += call_malloc
	frame_code += '\xc3'							#ret

	bin_write(binary, frame_section.virtual_address, frame_code, 'amd64')
	patch_call(binary, call_addr, frame_section.virtual_address, 'amd64')

	binary.write(sys.argv[1] + '_patch')

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print("Usage: <elf> <call_malloc_addr>")
		sys.exit(1)
	write_to_frame()