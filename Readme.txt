HOW TO USE:
	-first of all install libssh2 and fuselib
	-compile using ./compile.sh
	-run:
		./fuse username@server.com --mountpoint /mnt/empty_folder
	-for more details, try this:	
		./fuse --help 

TODO:
	-split sftp.cpp into multiple files, a file for each class
	-add support for remote file editing
	-add option for logging in using a key file
