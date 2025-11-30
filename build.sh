#!/usr/bin/env bash

make clean && make
python ./bin/psptools/pack_ms_game.py --vanity 'Leaf Cleaner' EBOOT.PBP EBOOT.PBP

if [ -d "PSP" ]; then
	rm *.zip
	rm -rf PSP
fi

mkdir -p PSP/GAME/LeafCleaner

mv EBOOT.PBP PSP/GAME/LeafCleaner/

zip -r `basename $(pwd)`.zip PSP README.md
