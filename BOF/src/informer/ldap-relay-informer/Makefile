BOFNAME := ldap-relay-informer
COMINCLUDE := -I ../../common
LIBINCLUDE := -lwldap32 -ldnsapi
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF 
	#$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c entry.c -DBOF
	mkdir -p ../../../informer/$(BOFNAME) 
	mv $(BOFNAME)*.o ../../../informer/$(BOFNAME)

test:
	$(CC_x64) entry.c -g $(COMINCLUDE) $(LIBINCLUDE)  -o $(BOFNAME).x64.exe
	#$(CC_x86) entry.c -g $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

clean:
	rm $(BOFNAME).*.exe 
