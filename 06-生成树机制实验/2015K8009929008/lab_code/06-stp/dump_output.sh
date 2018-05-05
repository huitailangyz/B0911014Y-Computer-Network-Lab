#!/bin/bash

for i in `seq 1 6`;
do
	echo "NODE b$i dumps:";
	tail -9 b$i-output.txt;
	echo "";
done
