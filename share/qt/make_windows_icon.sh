#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/Cart.ico

convert ../../src/qt/res/icons/Cart-16.png ../../src/qt/res/icons/Cart-32.png ../../src/qt/res/icons/Cart-48.png ${ICON_DST}
