#!/bin/bash

MUTEX="/tmp/CTIS-VT-bridge-mutex"

if test -f $MUTEX;
then
	exit
else
	touch $MUTEX
	docker-compose up --abort-on-container-exit
	rm $MUTEX
fi
