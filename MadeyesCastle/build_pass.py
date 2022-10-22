#!/usr/bin/env python3
############################################################
# To run this and get successful output, you must first
# pull the specified passfile from the samba share
# discovered during enumeration.
############################################################

passfile = "samba/spellnames.txt"
outfile = "big_spells.txt"

def gen_spell(filename):
    with open(filename,'r') as fptr:
        for line in fptr:
            yield line.strip('\n')
    return

spell_iter = gen_spell(passfile)

print("[*] Generating File")
with open(outfile,'a') as fptr:
    for spell in spell_iter:
        fptr.write("{0}\n".format(spell))
        for i in range(1000):
            fptr.write("{0}{1}\n".format(spell,i))

print("[+] File generated")

