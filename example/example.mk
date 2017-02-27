LDFLAGS=-Wall -lamip -L../src/ -I../src/

ami_example: ami_example.c
	$(CC) -o $@ $< $(LDFLAGS)

.PHONY: clean
clean:
	rm -f ami_example
