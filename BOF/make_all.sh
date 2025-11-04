#!/bin/bash

cd src/informer
ls | while read dir; do
    if [[ -d $dir ]]; then
        cd $dir
        if [[ -f "Makefile" ]]; then
            make >/dev/null
            echo "- $dir"
        fi
        cd ..
    fi
done
cd ../..

