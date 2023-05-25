### simplefirewall: a packet filtering firewall for GNU/Linux systems
simplefirewall is a simple packet filtering firewall, written in C, for GNU/Linux based systems. It uses Netfilter's hooks to watch the inbound and outbound packets of a computer in a network. Note my linux kernel lib version is 5.15.0-67-generic.

#### File Structure
Under the Kernel directory:

``kernelfw.c`` : A Linux Kernel module (LKM) which implements Netfilter's hooks mainly ``NF_INET_LOCAL_IN`` and 
``NF_INET_LOCAL_OUT`` to filter the packets.

``kernelfw.h`` : Has all the structure details and other macros needed to implement the rules of simplefirewall (the details 
in this header file must be consistent with the details in the user space simplefirewall header).

Under the Userspace directory:
``userfw.c`` : This tool acts as the user space program for setting simplefirewall's packet filtering rules. It uses 
"getopt.h" header to parse the arguments sent to it. Please get used to its arguments' notation. Will include the "help" 
details to the code after some clean-up work.

``userfw.h`` : Contains macros and structs as in userfw.c. All the fields in the struct my_ipt are initialised in 
userfw.c and are sent to kernel firewall through /proc.

#### Usage 
Follow the steps given below to insert simplefw  into the kernel.

        cd Kernel
        make
        sudo insmod kernelfw.ko


Run the user-space ``userfw`` program after compiling it. Follow the steps given below to test it.
        
        gcc -o fw userfw.c
        sudo ./fw --in --proto ALL --action BLOCK
        ping www.baidu.com

What do you observe? You should NOT be able to ping any server since you have written a simplefirewall rule to block all
the incoming packets bounded to your system. Also you can try opening a webpage in your browser which should be 
unsuccessful. If not, then there is some problem with passing/registering the rules with the kernel firewall.

Play around with some more rules of simplefirewall by going through its source until I update a "help" section which
lists out all the parameters for simplefirewall's rules.

Good luck!
