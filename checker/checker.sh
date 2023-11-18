#!/bin/bash

cd "$(dirname "$0")" || exit 1
cd ..

make
if [ $? != 0 ]; then
	echo "Make failed, bailing out..." >&2
	exit 1
fi

sudo fuser -k 6653/tcp
sudo python3 checker/topo.py tests
