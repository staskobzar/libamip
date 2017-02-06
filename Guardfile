# Guardfile
#
guard :shell do
  watch(/configure\.ac/) do
    system("./bootstrap")
  end
  watch(/Makefile\.am/) do
    system("make clean")
    system("./configure --with-coverage")
  end
  watch(/Doxyfile\.in/) do
    system("make")
  end
  watch(/(src|test)\/(.+)\.(c|h|re)/) do
    system("make clean")
    system("make check || cat test/*_test.log")
    # system("make valgrind")
  end
end
