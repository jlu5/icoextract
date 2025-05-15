CFLAGS=-mwindows -g
PREFIX64=x86_64-w64-mingw32-
PREFIX32=i686-w64-mingw32-

all: testapp64.exe testapp64-nores.exe testapp64-noicon.exe \
	testapp64-smallonly.exe testapp64-with128.exe testapp64-with192.exe

bmps: testapp.png
	convert testapp.png -resize 16x16 tmp-testapp-16.bmp
	convert testapp.png -resize 32x32 tmp-testapp-32.bmp
	convert testapp.png -resize 48x48 tmp-testapp-48.bmp
	convert testapp.png -resize 16x16 -depth 8 -remap netscape: -transparent black tmp-testapp8bpp-16.bmp
	convert testapp.png -resize 32x32 -depth 8 -remap netscape: -transparent black tmp-testapp8bpp-32.bmp
	convert testapp.png -resize 48x48 -depth 8 -remap netscape: -transparent black tmp-testapp8bpp-48.bmp

# icon with standard sizes: 16x16, 32x32, 48x48, 256x256
testapp.ico: testapp.png bmps
	convert testapp.png tmp-testapp*.bmp testapp.ico

# Small icon (only up to 48x48)
testapp-smallonly.ico: testapp.png bmps
	convert tmp-testapp-*.bmp testapp-smallonly.ico

# All standard sizes + 128x128
testapp-with128.ico: testapp.png bmps
	convert testapp.png -resize 128x128 tmp-testapp-128.png
	convert testapp.png tmp-testapp*.bmp tmp-testapp*.png testapp-with128.ico

# All small sizes + 128x128 + 192x192 (excluding 256x256)
testapp-with192.ico: testapp-with128.ico
	convert testapp.png -resize 192x192 tmp-testapp-192.png
	convert tmp-testapp*.bmp tmp-testapp-128.png tmp-testapp-192.png testapp-with192.ico

# Build with icon + version resource
define build-with-icon =
cat testapp-base.rc > tmp-testapp$(ICOSUFFIX).rc
echo "2 ICON testapp$(ICOSUFFIX).ico" >> tmp-testapp$(ICOSUFFIX).rc
$(PREFIX64)windres tmp-testapp$(ICOSUFFIX).rc -O coff -o tmp-testapp64$(ICOSUFFIX).res
$(PREFIX64)gcc $(CFLAGS) -o testapp64$(ICOSUFFIX).exe testapp.c tmp-testapp64$(ICOSUFFIX).res
$(PREFIX32)windres tmp-testapp$(ICOSUFFIX).rc -O coff -o tmp-testapp32$(ICOSUFFIX).res
$(PREFIX32)gcc $(CFLAGS) -o testapp32$(ICOSUFFIX).exe testapp.c tmp-testapp32$(ICOSUFFIX).res
endef

testapp64.exe testapp32.exe: testapp.c testapp.ico
	$(build-with-icon)

testapp64-smallonly.exe testapp32-smallonly.exe: ICOSUFFIX=-smallonly
testapp64-smallonly.exe testapp32-smallonly.exe: testapp.c testapp-smallonly.ico
	$(build-with-icon)

testapp64-with128.exe testapp32-with128.exe: ICOSUFFIX=-with128
testapp64-with128.exe testapp32-with128.exe: testapp.c testapp-with128.ico
	$(build-with-icon)

testapp64-with192.exe testapp32-with192.exe: ICOSUFFIX=-with192
testapp64-with192.exe testapp32-with192.exe: testapp.c testapp-with192.ico
	$(build-with-icon)

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
