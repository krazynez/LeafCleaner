TARGET = main

OBJS = main.o

LIBS = -lpspdebug -lpsppower -lpspexploit -lpsprtc


PSP_EBOOT_TITLE = Leaf Cleaner
PSP_EBOOT_ICON = data/ICON0.PNG
PSP_EBOOT_SND0 = data/SND0.AT3


EXTRA_TARGETS = EBOOT.PBP


BUILD_PRX = 1


PSPSDK=$(shell psp-config -p)
include $(PSPSDK)/lib/build.mak
