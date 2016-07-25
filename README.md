# myhook_add_tcp_option
use netfilter to add tcp option for output packets

readme：
      project description:  add a user-define tcp option on the output packet using netfilter hook;
      step1:  download source file and Makefile;
      step2:  make,  to generate the module file: myhook_add_tcp_option.ko
      step3:  insmod myhook_add_tcp_option,  to install my hook;
      step4:  do a test to access some websit and tcpdump the packets;
      step5:  you will see output packets with user-defined tcp option, the test is passed.
      

