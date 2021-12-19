import sys
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def main():
	choice = int(input("""\
What do you want to do?
1) sections
2) disass
3) relocations
4) quit\n"""))

	path = str(input("Which file do you want to analyze?\n"))

	if choice == 1:
		with open(path, 'rb') as f:
		    e = ELFFile(f)
		    for section in e.iter_sections():
		        print(hex(section['sh_addr']), section.name)

	elif choice == 2:
		with open(path, 'rb') as f:
		    elf = ELFFile(f)
		    code = elf.get_section_by_name('.text')
		    ops = code.data()
		    addr = code['sh_addr']
		    md = Cs(CS_ARCH_X86, CS_MODE_64)
		    for i in md.disasm(ops, addr):        
		        print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')

	elif choice == 3:
		with open(path, 'rb') as f:
		    e = ELFFile(f)
		    for section in e.iter_sections():
		        if isinstance(section, RelocationSection):
		            print(f'{section.name}:')
		            symbol_table = e.get_section(section['sh_link'])
		            for relocation in section.iter_relocations():
		                symbol = symbol_table.get_symbol(relocation['r_info_sym'])
		                addr = hex(relocation['r_offset'])
		                print(f'{symbol.name} {addr}')

	else:
		print("Bye")
		exit(0)

main()