CFLAGS=-mwindows -g
PREFIX64=x86_64-w64-mingw32-
PREFIX32=i686-w64-mingw32-

all: testapp64.exe testapp64-nores.exe testapp64-noicon.exe testapp32.exe testapp32-nores.exe testapp32-noicon.exe

# icon with standard sizes: 16x16, 32x32, 48x48, 256x256
testapp.ico testapp-small.ico testapp-128.ico: testapp.png
	convert testapp.png -resize 16x16 tmp-testapp-16.bmp
	convert testapp.png -resize 32x32 tmp-testapp-32.bmp
	convert testapp.png -resize 48x48 tmp-testapp-48.bmp
	convert testapp.png -resize 16x16 -depth 8 -remap netscape: -transparent black tmp-testapp8bpp-16.bmp
	convert testapp.png -resize 32x32 -depth 8 -remap netscape: -transparent black tmp-testapp8bpp-32.bmp
	convert testapp.png -resize 48x48 -depth 8 -remap netscape: -transparent black tmp-testapp8bpp-48.bmp
	convert testapp.png tmp-testapp*.bmp testapp.ico

tmp-testapp.rc: testapp-base.rc testapp-icon.rc
	cat testapp-base.rc > tmp-testapp.rc
	cat testapp-icon.rc >> tmp-testapp.rc

# Build with icon + version resource
testapp64.exe testapp32.exe: testapp.c tmp-testapp.rc testapp.ico
	$(PREFIX64)windres tmp-testapp.rc -O coff -o tmp-testapp64.res
	$(PREFIX64)gcc $(CFLAGS) -o testapp64.exe testapp.c tmp-testapp64.res
	$(PREFIX32)windres tmp-testapp.rc -O coff -o tmp-testapp32.res
	$(PREFIX32)gcc $(CFLAGS) -o testapp32.exe testapp.c tmp-testapp32.res

# Build with only version resource
testapp64-noicon.exe testapp32-noicon.exe: testapp.c
	$(PREFIX64)windres testapp-base.rc -O coff -o tmp-testapp64-noicon.res
	$(PREFIX64)gcc $(CFLAGS) -o testapp64-noicon.exe testapp.c tmp-testapp64-noicon.res
	$(PREFIX32)windres testapp-base.rc -O coff -o tmp-testapp32-noicon.res
	$(PREFIX32)gcc $(CFLAGS) -o testapp32-noicon.exe testapp.c tmp-testapp32-noicon.res

# Build with no resource info at all
testapp64-nores.exe testapp32-nores.exe: testapp.c
	$(PREFIX64)gcc $(CFLAGS) -o testapp64-nores.exe testapp.c
	$(PREFIX32)gcc $(CFLAGS) -o testapp32-nores.exe testapp.c


clean:
	$(RM) tmp*.* *.ico *.exe
