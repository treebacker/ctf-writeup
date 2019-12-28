import sys
import lief
from pwn import *

def swap_libsym(obj, a, b):
    symbol_a = next(filter(lambda e : e.name == a, obj.dynamic_symbols))
    symbol_b = next(filter(lambda e : e.name == b, obj.dynamic_symbols))
    b_name = symbol_b.name
    symbol_b.name = symbol_a.name
    symbol_a.name = b_name

def swap_binsym(obj, a, b):
    symbol_a = next(filter(lambda e : e.name == a, obj.imported_symbols))
    symbol_b = next(filter(lambda e : e.name == b, obj.imported_symbols))
    b_name = symbol_b.name
    symbol_b.name = symbol_a.name
    symbol_a.name = b_name

def patch():
	binary = lief.parse(sys.argv[1])
	swap_binsym(binary, 'printf', sys.argv[2])
	binary.write('./p_fmt')

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print("Usage: {} <elf binary> <fake_printf>".format(sys.argv[0]))
		sys.exit(1)
	patch()