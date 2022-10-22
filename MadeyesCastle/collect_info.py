#!/usr/bin/env python3
############################################################
# This script combines three discovered files to leak
# login information for a specific user.
############################################################

f3 = "db_notes.txt"
f1 = "names.txt"
f2 = "hashes.txt"

with open(f1,'r') as fptr:
    line1 = fptr.readlines()

with open(f2,'r') as fptr:
    line2 = fptr.readlines()

with open(f3,'r') as fptr:
    line3 = fptr.readlines()

line1 = [line.strip('\n') for line in line1]
line2 = [line.strip('\n') for line in line2]
line3 = [line.strip('\n') for line in line3]

full_line = list(zip(line1,line2))
full_line = list(zip(full_line,line3))

[print(line) for line in full_line]

