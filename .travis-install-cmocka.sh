#!/bin/bash

cd /tmp
git clone git://git.cryptomilk.org/projects/cmocka.git
cd cmocka
git checkout tags/cmocka-1.0.1 -b 1.0.1
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ..
make
sudo make install
