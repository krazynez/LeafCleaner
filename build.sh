#!/usr/bin/env bash

make clean && make
python ./bin/psptools/pack_ms_game.py --vanity 'Leaf Cleaner' EBOOT.PBP EBOOT.PBP
