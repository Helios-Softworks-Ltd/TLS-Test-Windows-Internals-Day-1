// File: source.cpp
// Path: /source.cpp
// Created Date: Thursday May 21st 2026
// Author: Helios Softworks Ltd. (director@helios-softworks.com)
//
// Copyright (c) 2025 Helios Softworks Ltd. All rights reserved.

#include <print>
#include <windows.h>

int main() {
	std::println( "TLS Test" );
	/*
	Test one
	--------------
	Functions Used: TlsAlloc, TlsSetValue, TlsGetValue, TlsFree

	Expected Output: TLS value: 42
	*/
	const auto tls_index = TlsAlloc();
	if ( tls_index == TLS_OUT_OF_INDEXES ) {
		std::println( "Failed to allocate TLS index" );
		return 1;
	}
	if ( !TlsSetValue( tls_index, reinterpret_cast<LPVOID>( 42 ) ) ) {
		std::println( "Failed to set TLS value" );
		return 1;
	}
	const auto value = TlsGetValue( tls_index );
	if ( value == nullptr ) {
		std::println( "Failed to get TLS value" );
		return 1;
	}
	std::println( "TLS value: {}", reinterpret_cast<std::uintptr_t>( value ) );
	if ( !TlsFree( tls_index ) ) {
		std::println( "Failed to free TLS index" );
		return 1;
	}

	/*
	Test two
	--------------
	Intrinsics Used: thread_local

	Expected Output: Thread local value: 42
	--------------
	*/
	thread_local int thread_local_value = 42;
	std::println( "Thread local value: {}", thread_local_value );
	return 0;
}
