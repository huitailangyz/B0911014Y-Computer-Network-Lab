all: worker master

worker: worker.c
	gcc -Wall -g worker.c -o worker

master: master.c
	gcc -Wall -g master.c -o master -lpthread

clean:
	@rm worker master
