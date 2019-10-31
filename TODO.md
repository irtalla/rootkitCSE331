Stack Smashing Ultimate

Linux rootkit project specifications  

Required Technologies:  
. C  
. Linux kernel 2.6 (OS = Ubuntu 11.04)

TODO:  
. highjack syscalls (write, readdir, etc) to hide kernel module and any relevant
  directories (Ian)  
. create backdoor account and hide information from user  
. hide kernel module from process table  
. elevate hidden user's permissions on demand by using a local privilege-escalation
  vulnerability (Kevin)  
