APPS := tcprtt tcprtt_tp

CC := clang
CFLAGS := -g -Wall -O2
LDLIBS += -lelf -lz
LDLIBS += /usr/lib64/libbpf.a

all: $(APPS)

$(APPS): %: %.c %.bpf.o %.skel.h
	$(CC) $(CFLAGS) $(filter %.c,$^) $(LDLIBS) -o $@

%.bpf.o: %.bpf.c
	$(CC) $(CFLAGS) -c -target bpf $< -o $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

clean:
	rm -f $(BPF_APPS) *.o *.skel.h