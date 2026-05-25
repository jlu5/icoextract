CFLAGS=-mwindows -g
MINGW64=x86_64-w64-mingw32-
MINGW32=i686-w64-mingw32-

.PHONY: all win64 win32 win16 clean

WATCOM ?= /opt/watcom
WCL_EXE := $(shell command -v wcl 2>/dev/null)
DOCKER_EXE := $(shell command -v docker 2>/dev/null)
WCL_FLAGS := -k -bt=windows -ml -l=windows
WRC_FLAGS := -q -bt=windows

# OpenWatcom is not available in most distros. For convenience, this will try a
# community Docker image if it is not already installed
ifneq ($(WCL_EXE),)
    WCL = INCLUDE="$(WATCOM)/h:$(WATCOM)/h/win wcl $(WCL_FLAGS)
    WRC = wrc $(WRC_FLAGS)
else ifneq ($(DOCKER_EXE),)
	OPENWATCOM_DOCKER = docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		--network none \
		-v $(CURDIR):/src \
		-e INCLUDE="$(WATCOM)/h:$(WATCOM)/h/win" \
		ghcr.io/arlaneenalra/watcom-docker
    WCL = $(OPENWATCOM_DOCKER) wcl $(WCL_FLAGS)
	WRC = $(OPENWATCOM_DOCKER) wrc $(WRC_FLAGS)
endif

# Win16 is excluded by default as it requires a different compiler
all: win64 win32

win64: testapp64.exe testapp64-nores.exe testapp64-noicon.exe \
	testapp64-with128.exe testapp64-with192.exe \
	testapp64-string-res.exe

win32: testapp32.exe testapp32-nores.exe testapp32-noicon.exe \
	testapp32-smallonly.exe

win16: testapp16.exe testapp16-nores.exe testapp16-noicon.exe

tmp-testapp-16.bmp: testapp.png
	convert testapp.png -resize 16x16 tmp-testapp-16.bmp

tmp-testapp-32.bmp: testapp.png
	convert testapp.png -resize 32x32 tmp-testapp-32.bmp

tmp-testapp-48.bmp: testapp.png
	convert testapp.png -resize 48x48 tmp-testapp-48.bmp

# icon with standard sizes: 16x16, 32x32, 48x48, 256x256
testapp.ico: testapp.png tmp-testapp-16.bmp tmp-testapp-32.bmp tmp-testapp-48.bmp
	convert testapp.png tmp-testapp*.bmp testapp.ico

# Small icon (only up to 48x48)
testapp-smallonly.ico: testapp.png tmp-testapp-16.bmp tmp-testapp-32.bmp tmp-testapp-48.bmp
	convert tmp-testapp-*.bmp testapp-smallonly.ico

# All standard sizes + 128x128
testapp-with128.ico: testapp.png tmp-testapp-16.bmp tmp-testapp-32.bmp tmp-testapp-48.bmp
	convert testapp.png -resize 128x128 tmp-testapp-128.png
	convert testapp.png tmp-testapp*.bmp tmp-testapp*.png testapp-with128.ico

# All small sizes + 128x128 + 192x192 (excluding 256x256)
testapp-with192.ico: testapp-with128.ico
	convert testapp.png -resize 192x192 tmp-testapp-192.png
	convert tmp-testapp*.bmp tmp-testapp-128.png tmp-testapp-192.png testapp-with192.ico

# $(1) = Toolchain prefix
# $(2) = Base output name (e.g., testapp64-with128)
define build-mingw-target =
    $(1)windres tmp-$(2).rc -O coff -o $(2).o
    $(1)gcc $(CFLAGS) -o $(2).exe testapp.c $(2).o
endef

# Build with (optional) icon + version resource
# $(1) = architecture (64, 32, or empty for both)
# $(2) = resource ID (defaults to 2)
define build-testapp =
    $(eval ICON_FILE := $(filter %.ico,$^))
	$(eval APP_NAME := $(basename $@))
	$(eval RC_NAME := tmp-$(APP_NAME).rc)

    cp testapp-base.rc $(RC_NAME)
	$(if $(ICON_FILE), \
        echo "$(if $(2),$(2),2) ICON $(ICON_FILE)" >> $(RC_NAME) \
    )

    $(if $(filter 64 $(1),$(if $(1),$(1),64)), \
        $(call build-mingw-target,$(MINGW64),$(APP_NAME)) \
    )
    $(if $(filter 32 $(1),$(if $(1),$(1),32)), \
        $(call build-mingw-target,$(MINGW32),$(APP_NAME)) \
    )
endef

testapp64.exe testapp32.exe: testapp.c testapp.ico
	$(call build-testapp,,)

testapp32-smallonly.exe: testapp.c testapp-smallonly.ico
	$(call build-testapp,32,)

testapp64-with128.exe: testapp.c testapp-with128.ico
	$(call build-testapp,64,)

testapp64-with192.exe: testapp.c testapp-with192.ico
	$(call build-testapp,64,)

testapp64-string-res.exe: testapp.c testapp.ico
	$(call build-testapp,32,MY_APP_ICON)

# Build with only version resource
testapp64-noicon.exe testapp32-noicon.exe: testapp.c
	$(call build-testapp,,)

# Build with no resource info at all
testapp64-nores.exe testapp32-nores.exe: testapp.c
	$(MINGW64)gcc $(CFLAGS) -o testapp64-nores.exe testapp.c
	$(MINGW32)gcc $(CFLAGS) -o testapp32-nores.exe testapp.c

## Win16
testapp16-nores.exe: testapp.c
	$(WCL) testapp.c -fe=testapp16-nores.exe -fo=testapp16.o

testapp16-noicon.exe: testapp16-nores.exe
	cp testapp16-nores.exe tmp-testapp16-noicon.exe
	$(WRC) testapp16-base.rc tmp-testapp16-noicon.exe
	mv tmp-testapp16-noicon.exe testapp16-noicon.exe

testapp16.exe: testapp16-nores.exe testapp-smallonly.ico
	cp testapp16-base.rc tmp-testapp16.rc
	echo 'IDI_APPICON ICON "testapp-smallonly.ico"' >> tmp-testapp16.rc
	cp testapp16-nores.exe tmp-testapp16.exe
	$(WRC) tmp-testapp16.rc tmp-testapp16.exe
	mv tmp-testapp16.exe testapp16.exe

clean:
	$(RM) tmp*.* *.ico *.exe *.o *.res
