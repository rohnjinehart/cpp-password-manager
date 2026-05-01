cmake_minimum_required(VERSION 3.16)
project(PasswordManager VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_executable(PasswordManager WIN32
        src/main.cpp
        src/crypto.cpp
        src/vault.cpp
        src/gui.cpp
        resources/resource.rc
    )
    target_include_directories(PasswordManager PRIVATE include)
    target_link_libraries(PasswordManager PRIVATE user32 gdi32 comctl32 shell32 comdlg32)
    target_compile_definitions(PasswordManager PRIVATE UNICODE _UNICODE)
    # Enable visual styles (comctl32 v6)
    set_target_properties(PasswordManager PROPERTIES
        LINK_FLAGS "/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\""
    )
endif()
