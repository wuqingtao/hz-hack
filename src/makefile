cc := gcc
include := -I./
cflags := -Wall
lflags := 
bin := bin/hztrack
src := $(notdir $(wildcard ./*.cc))
obj := $(src:%.cc=obj/%.o)

$(bin): $(obj)
	@test -d bin || mkdir bin
	$(cc) $(lflags) -o $@ $^

$(obj): obj/%.o: ./%.cc
	@test -d obj || mkdir obj
	$(cc) $(include) $(cflags) -c $< -o $@

.PHONY: clean
clean:
	-rm -rf obj bin
