# .bashrc

# User specific aliases and functions

#alias rm='rm -i'
#alias cp='cp -i'
#alias mv='mv -i'
alias Cl='clear'
alias CL='clear'
alias lla='ll -a'
alias Ack='ack -w'
alias reboot='ls'
alias ping='ping -c 5'


# Source global definitions
if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi
PS1='[\W]\$'
