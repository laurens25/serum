CC = gcc
LD = gcc

DISTRO_DEF = $(shell sh ./get-distro.sh)
GIT_INFO = $(shell sh ./get-git-info.sh)
ELF_INTERP = $(shell sh ./get-elf-interpreter.sh)
LS_MCHECK =
LS_PTHREADS = $(shell sh ./get-pthreads.sh)

CFLAGS = \
	-fPIC -fstack-protector-strong -I. \
	-DMAKEFILE=1 -DDISTRO=\"$(DISTRO_DEF)\" \
	$(GIT_INFO) \
	$(ELF_INTERP)


all: release test

all_dbg: debug test

all_dbg_origin: debug_origin test

clean:
	@echo -n "Cleaning..."
	@rm -f bin/libserum.so
	@rm -f bin/test
	@rm -Rf obj/libserum
	@rm -Rf obj/test
	@echo " done."
	@echo

run_test:
	@bin/test

r: clean all_dbg

r_o: clean all_dbg_origin

rt: r run_test

rt_o: r_o run_test

d: all_dbg

d_o: all_dbg_origin

dt: d run_test

dt_o: d_o run_test



obj/%.o: %.c
	@echo -n "| $@"
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) -c $^ -o $@
	@echo " (done)"



bin/libserum.so: CFLAGS += -DLIBSERUM_EXPORTS=1
bin/libserum.so: $(addprefix obj/, $(patsubst %.c, %.o, $(shell find libserum -type f -name '*.c')))
	@echo -n "+-> $@"
	@mkdir -p $(@D)
	@$(LD) -o $@ -shared $(LS_MCHECK) $(LS_PTHREADS) -Wl,-e,interp_entry $^
	@echo " (done)"
	@echo

bin/test: bin/libserum.so
bin/test: $(addprefix obj/, $(patsubst %.c, %.o, $(shell find test -type f -name '*.c')))
	@echo -n "+-> $@"
	@mkdir -p $(@D)
	@$(CC) -lserum -o $@ $^
	@echo " (done)"
	@echo



debug: CFLAGS += -g -DDEBUG
debug: LS_MCHECK += $(shell sh ./get-mcheck.sh)
debug: lib

debug_origin: CFLAGS += -ULS_LOG_ORIGIN -DLS_LOG_ORIGIN=1
debug_origin: debug

release: CFLAGS += -O3 -DRELEASE
release: lib



lib: bin/libserum.so

test: bin/test
