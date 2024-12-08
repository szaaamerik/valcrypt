# valcrypt

Integer encryption based on intrins for C++11 or up.<br/>
Supported compilers: `MinGW`, `GCC` & `MSVC`.

Inspiration: [a7t0fwa7/val_crypt](https://github.com/a7t0fwa7/val_crypt)

## Features

- Provides lightweight integer encryption.
- Supports as far back as C++11.
- Simple API for integrating into your C++ projects.

## Usage

1. Download and include the valcrypt files in your project.
2. For MinGW/GCC you might also need to ensure SSE4.1 intrins are enabled.
```cmake
target_compile_options(YOUR_TARGET PRIVATE -msse4.1)
```

> [!WARNING]
>It is highly recommended to disable optimizations for `valcrypt` to prevent the intrinsics from being optimized away.<br/>
>Below are the CMake configurations to achieve this:

MSVC:
```cmake
set_source_files_properties(CENCRYPTEDVALUE_FILEPATH PROPERTIES COMPILE_OPTIONS "/Od")
```

MinGW/GCC:
```cmake
set_source_files_properties(CENCRYPTEDVALUE_FILEPATH PROPERTIES COMPILE_OPTIONS "-O0")
```
## Configuration

| `#define`                                 | Effect                                                                                  |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `VALCRYPT_NOINLINE`                       | Will never inline any major function related to valcrypt                                |

## Example Usage

```cpp
#include "CEncryptedValue.hpp"

#include <iostream>

int main() {
    // note: This will NOT encrypt '42' at compile time.
    //       It will still be seen in disassembly.
    //       This functionality might be integrated to this repository soon.
    valcrypt::CEncryptedValue<int> encrypted(42);
    std::cout << "Encrypted value: " << encrypted.GetEncrypted() << '\n';

    int decryptedValue = encrypted.GetDecrypted();
    std::cout << "Decrypted value: " << decryptedValue << '\n';

    valcrypt::CEncryptedValue<int> otherEncrypted(58);
    auto result = encrypted + otherEncrypted;
    std::cout << "Encrypted result of addition: " << result.GetEncrypted() << '\n';

    return 0;
}
```

## Demo

Here is an IDA 9.0 decompilation of how `valcrypt` with MSVC looks like.

![image](https://github.com/user-attachments/assets/d288101d-c0d2-407f-8660-76c127312341)
