CFLAGS=-mwindows -g
PREFIX64=x86_64-w64-mingw32-
PREFIX32=i686-w64-mingw32-

all: testapp64.exe testapp64-nores.exe testapp64-noicon.exe testapp32.exe testapp32-nores.exe testapp32-noicon.exe

testapp.ico: testapp.png
	convert testapp.png -resize 16x16 tmp-testapp-16.bmp
	convert testapp.png -resize 32x32 tmp-testapp-32.bmp
	convert testapp.png -resize 48x48 tmp-testapp-48.bmp
	convert testapp.png -resize 16x16 -depth 8 -remap netscape: -transparent black tmp-testapp246-16.bmp
	convert testapp.png -resize 32x32 -depth 8 -remap netscape: -transparent black tmp-testapp256-32.bmp
	convert testapp.png -resize 48x48 -depth 8 -remap netscape: -transparent black tmp-testapp256-48.bmp
	convert testapp.png tmp-testapp*.bmp testapp.ico

testapp.rc: testapp-base.rc testapp-icon.rc
	$(shell cat testapp-base.rc > testapp.rc)
	$(shell cat testapp-icon.rc >> testapp.rc)

testapp64.res: testapp.rc testapp.ico
	$(PREFIX64)windres testapp.rc -O coff -o testapp64.res

testapp64-noicon.res: testapp-base.rc
	$(PREFIX64)windres testapp-base.rc -O coff -o testapp64-noicon.res

# Build with icon + version resource
testapp64.exe: testapp.c testapp64.res
	$(PREFIX64)gcc $(CFLAGS) -o testapp64.exe testapp.c testapp64.res

# Build with only version resource
testapp64-noicon.exe: testapp.c testapp64-noicon.res
	$(PREFIX64)gcc $(CFLAGS) -o testapp64-noicon.exe testapp.c testapp64-noicon.res

# Build with no resource info at all
testapp64-nores.exe: testapp.c
	$(PREFIX64)gcc $(CFLAGS) -o testapp64-nores.exe testapp.c


testapp32.res: testapp.rc testapp.ico
	$(PREFIX32)windres testapp.rc -O coff -o testapp32.res

testapp32-noicon.res: testapp-base.rc
	$(PREFIX32)windres testapp-base.rc -O coff -o testapp32-noicon.res

testapp32.exe: testapp.c testapp32.res
	$(PREFIX32)gcc $(CFLAGS) -o testapp32.exe testapp.c testapp32.res

testapp32-noicon.exe: testapp.c testapp32-noicon.res
	$(PREFIX32)gcc $(CFLAGS) -o testapp32-noicon.exe testapp.c testapp32-noicon.res

testapp32-nores.exe: testapp.c
	$(PREFIX32)gcc $(CFLAGS) -o testapp32-nores.exe testapp.c


clean:
	$(RM) tmp*.bmp testapp.ico testapp*.res *.exe tmp*.ico testapp.rc
