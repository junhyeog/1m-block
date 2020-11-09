# -*- coding: utf-8 -*-
"""
Created on Mon Nov  9 21:29:57 2020

@author: User
"""

import csv

l = []
# index,site format
with open('top-1m.csv', 'r') as csvfile:
    block_csv = csv.reader(csvfile, delimiter=',')
    for row in block_csv:
        l.append(row[-1])
print("found {} lines".format(len(l)))

l.sort()
print("sorted list")

with open('top-1m.txt', 'w') as txtfile:
    for site in l:
        txtfile.write(site + '\n')

print("---fin---")