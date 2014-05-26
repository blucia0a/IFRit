cmake_minimum_required(VERSION 2.8)

add_llvm_loadable_module(IFRIT
	InsertDRDCalls.cpp
)

set_target_properties(IFRIT PROPERTIES
	COMPILE_FLAGS "-fno-rtti -fvisibility-inlines-hidden -std=c++11 -stdlib=libc++"
)
