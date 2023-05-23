all:
	g++ main.cc -lcrypto -o ./snakeTest
clean:
	rm ./snakeTest
