BOFNAME := ldap-bypass-informer
COMINCLUDE := -I ../../common
LIBINCLUDE := -lws2_32 -lsecur32
CC_x64 := x86_64-w64-mingw32-gcc

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF
	mkdir -p ../../../informer/$(BOFNAME)
	mv $(BOFNAME)*.o ../../../informer/$(BOFNAME)

