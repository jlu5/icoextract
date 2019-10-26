CFLAGS=-mwindows -g
PREFIX64=x86_64-w64-mingw32-
PREFIX32=i686-w64-mingw32-

all: testapp32.exe testapp64.exe

testapp.ico: testapp.png
	convert testapp.png -resize 16x16 tmp-testapp-16.bmp
	convert testapp.png -resize 32x32 tmp-testapp-32.bmp
	convert testapp.png -resize 48x48 tmp-testapp-48.bmp
	convert testapp.png -resize 16x16 -depth 8 -remap netscape: -transparent black tmp-testapp246-16.bmp
	convert testapp.png -resize 32x32 -depth 8 -remap netscape: -transparent black tmp-testapp256-32.bmp
	convert testapp.png -resize 48x48 -depth 8 -remap netscape: -transparent black tmp-testapp256-48.bmp
	convert testapp.png tmp-testapp*.bmp testapp.ico

testapp64.res: testapp.rc testapp.ico
	$(PREFIX64)windres testapp.rc -O coff -o testapp64.res

testapp64.exe: testapp.c testapp64.res
	$(PREFIX64)gcc $(CFLAGS) -o testapp64.exe testapp.c testapp64.res

testapp32.res: testapp.rc testapp.ico
	$(PREFIX32)windres testapp.rc -O coff -o testapp32.res

testapp32.exe: testapp.c testapp32.res
	$(PREFIX32)gcc $(CFLAGS) -o testapp32.exe testapp.c testapp32.res

clean:
	$(RM) tmp*.bmp testapp.ico testapp*.res *.exe tmp*.ico
