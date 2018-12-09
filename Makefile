csv2mmdb: mmdb_write.o csv_read.o tree.o main.o
	$(CC) -g $^ -o $@

clean:
	rm -f csv2mmdb *.o
