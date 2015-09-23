#!/usr/bin/env bash

gcc -o launcher template.o program.o tag.o salt.o iv.o -lrt -lssl -lcrypto

rm {program,tag,salt,iv}{,.o}

strip launcher
