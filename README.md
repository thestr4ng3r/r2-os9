
# r2-os9

Basic radare2 bin plugin to read Microware OS-9 memory modules.

Created after the OS-9 2.4 Technical Manual, which is the one that applies to CD-RTOS, the operating system of Philips CD-i consoles.

Working features:
* Parsing header and additional header values (see `i` and `ih`)
* Sections for header, body and crc (`iS`)
* Entrypoint (`ie`)

## Building and Installing

```
mkdir build && cd build
cmake ..
make && sudo make install
```
Run `make install` without `sudo` if you installed radare2 in your user's directory.

## About

Created by Florian Märkl: https://www.metallic.software

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.