csv2mmdb: main.c
	$(CC) -g $< -o $@

clean:
	rm -f csv2mmdb *.o
