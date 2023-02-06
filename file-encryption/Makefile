CC=gcc
CFLAGS += -Wall -O0 -g3
LDLIBS += -lgnutls
srcs := $(shell find . -name \*.c)

.PHONY: all
all: input.txt $(srcs:%.c=%) ca_cert.pem crl.pem cert.pem

input.txt:
	echo "Hello World" >> input.txt

ca_cert.pem:
	echo -ne "ca\ncert_signing_key" > temp
	certtool --generate-privkey > ca_key.pem
	certtool --generate-self-signed \
		--template temp \
		--load-privkey ca_key.pem \
		--outfile ca_cert.pem
	rm temp

crl.pem:
	echo "expiration_days = 700" > temp
	certtool --generate-crl --load-ca-privkey ca_key.pem \
		--template temp \
		--load-ca-certificate ca_cert.pem \
		--outfile crl.pem
	rm temp

cert.pem:
	echo -ne "encryption_key\nsigning_key" > temp
	certtool --generate-privkey > key.pem
	certtool --generate-certificate \
		--template temp \
		--load-privkey key.pem \
		--load-ca-certificate ca_cert.pem \
		--load-ca-privkey ca_key.pem \
		--outfile cert.pem
	rm temp

.PHONY: clean
clean:
	rm -f $(srcs:%.c=%) $(srcs:%.c=%.d)
	rm -f *.txt *.img *.pem

.PRECIOUS : %.o
%.o : %.c ; $(COMPILE.c) $(OUTPUT_OPTION) $<
% : %.o ; @$(LINK.cpp) $(OUTPUT_OPTION) $^ $(LDLIBS)
