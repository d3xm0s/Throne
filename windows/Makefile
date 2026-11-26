CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -O2 -static -static-libgcc -static-libstdc++
LDLIBS = -ladvapi32 -lshell32 -lole32

throne-win.exe: throne_win.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f throne-win.exe
