default:
	gcc -fPIC -fno-stack-protector -c pam_bluetooth.c

install:
	ld -x --shared -o /lib64/security/pam_bluetooth.so pam_bluetooth.o
	touch /etc/security/authorized_bluetooth.conf
