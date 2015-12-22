# .bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
	. ~/.bashrc
fi

# User specific environment and startup programs

PATH=$PATH:$HOME/bin
PATH=$PATH:/home/work/opensource/Git/net-snmp/out/bin/
PATH=$PATH:/home/work/opensource/Git/net-snmp/out/sbin/
PATH=$PATH:/home/work/opensource/Git/net-snmp/test/script

export PATH
