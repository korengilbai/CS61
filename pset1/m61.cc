#define M61_DISABLE 1
#define TRAILER_LEN 6
#include "m61.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <limits.h>
#include <vector>

// memory allocation statistics struct. updated with allocation calls
m61_statistics mem_stats = { .heap_min = 0xFFFFFFFFFFFFFF, .heap_max = 0 }; 

// vector of pointers to metadata of user-allocated memory
std::vector<alloc_metadata*> alloc_ptrs;

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    // prevent integer overflow in determining total allocation size
    size_t alloc_size; 
    if(sz > ((uintptr_t) - (sizeof(alloc_metadata) + TRAILER_LEN))){
        alloc_size = sz;
    }
    else{
        alloc_size = sz + sizeof(alloc_metadata) + TRAILER_LEN;
    }

    // allocate memory for header metadata, payload, and trailing magic number
    alloc_metadata* alloc_ptr = (alloc_metadata*) base_malloc(alloc_size);

    // check for failed allocation, update stats accordingly
    if(alloc_ptr == nullptr){
        mem_stats.nfail++;
        mem_stats.fail_size += sz;
        return (void*) alloc_ptr;
    }

    // create a metadata struct to insert before user-allocated memory
    alloc_metadata md = { .allocation_size = sz, .mallocd = true, .active = true,
                            .file = file, .line = line};

    // insert metadata struct before user-allocated memory
    *alloc_ptr = md;

    // insert metadata pointer into record vector
    alloc_ptrs.push_back(alloc_ptr);

    // redirect pointer to payload
    alloc_ptr += 1; 

    // update number of memory allocations
    mem_stats.ntotal++;
    mem_stats.nactive++;

    // update number of bytes allocated
    mem_stats.total_size += sz;
    mem_stats.active_size += sz;

    // update max/min addresses
    if(((uintptr_t) alloc_ptr + sz) > mem_stats.heap_max){
        mem_stats.heap_max = (uintptr_t) alloc_ptr + sz;
    }
    if((uintptr_t) alloc_ptr < mem_stats.heap_min){
        mem_stats.heap_min = (uintptr_t) alloc_ptr;
    }

    // write 6-byte trailing magic number after user-allocated block  
    char* trailer_ptr = (char*) alloc_ptr + sz;
    const char* magic_number = "koren";
    memcpy(trailer_ptr, magic_number, 6);

    return (void*) alloc_ptr;
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void m61_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    // check for null pointer
    if(ptr == nullptr){
        return;
    }

    // determine whether the pointer isn't active or inside an allocated block
    bool ptr_is_active = false;
    for(int i = 0; i < (int) alloc_ptrs.size(); ++i){
        // check if the pointer is in the list of active allocated pointers
        if ((alloc_metadata*) ptr - 1 == alloc_ptrs[i]){
            ptr_is_active = true;
        }

        // check if pointer is inside an allocated block
        uintptr_t start_address = (uintptr_t) (alloc_ptrs[i] + 1);
        uintptr_t end_address = start_address + alloc_ptrs[i]->allocation_size;

        if((uintptr_t) ptr > start_address && (uintptr_t) ptr < end_address){
            unsigned long offset = (uintptr_t) ptr - start_address;
            fprintf(stderr, "MEMORY BUG: %s:%lu: invalid free of pointer %p, not allocated\n",
                    file, line, ptr);
            fprintf(stderr, "  %s:%lu: %p is %lu bytes inside a %lu byte region allocated here\n",
                    file, alloc_ptrs[i]->line, ptr, offset, alloc_ptrs[i]->allocation_size); 
            return;
        }
    }

    // retrieve the metadata of this allocation
    alloc_metadata* md_ptr = (alloc_metadata*) ptr - 1;  
    unsigned long alloc_size = md_ptr->allocation_size;
    bool mallocd = md_ptr->mallocd;
    bool active = md_ptr->active;

    // check for invalid free - not in heap
    if((uintptr_t) ptr < mem_stats.heap_min || (uintptr_t) ptr > mem_stats.heap_max){
        fprintf(stderr, "MEMORY BUG %s:%lu: invalid free of pointer %p, not in heap\n",
        file, line, ptr);
        return;
    }

    // check for invalid free - not allocated
    if(!mallocd){
        fprintf(stderr, "MEMORY BUG: %s:%lu: invalid free of pointer %p, not allocated\n",
        file, line, ptr);
        return;
    }

    // check for double free
    if(!active){
        fprintf(stderr, "MEMORY BUG %s:%lu: invalid free of pointer %p, double free\n",
        file, line, ptr);
        return;
    }
    
    // check if the pointer is not actively allocated (diabolical double free)
    if(!ptr_is_active){
        fprintf(stderr, "MEMORY BUG %s:%lu: invalid free of pointer %p, not in heap\n",
        file, line, ptr);
        return;
    }

    // detect if the memory block suffered a boundary write error
    const char* magic_number = "koren";
    char* trailing_ptr = (char*) ptr + md_ptr->allocation_size;
    if(memcmp(magic_number, trailing_ptr, 6) != 0){
        fprintf(stderr, "MEMORY BUG %s:%lu: detected wild write during free of pointer %p\n",
        file, line, ptr);
        abort();
    }

    // update number and size of active allocations
    mem_stats.nactive--;
    mem_stats.active_size -= alloc_size;

    // set the active flag to false (record double frees)
    md_ptr->active = false;

    // remove the ptr from the actively allocated pointers vector
    for(int i = 0; i < (int) alloc_ptrs.size(); ++i){
        if(alloc_ptrs[i] == md_ptr){
            alloc_ptrs.erase(alloc_ptrs.begin() + i);
            break;
        }
    }

    // free the ptr
    base_free(ptr);
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // protect against integer overflow - nmemb * sz < size_t
    if(nmemb > ULONG_MAX / sz){
        mem_stats.nfail += 1;
        mem_stats.fail_size += nmemb;
        return nullptr;
    }

    // calloc and return ptr
    void* ptr = m61_malloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// m61_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_get_statistics(m61_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(m61_statistics));
    // Your code here.
    *stats = mem_stats;
}


/// m61_print_statistics()
///    Print the current memory statistics.

void m61_print_statistics() {
    m61_statistics stats;
    m61_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
    for(int i = 0; i < (int) alloc_ptrs.size(); ++i){
        if(alloc_ptrs[i]->active){ // memory leak -- memory wasn't freed
            printf("LEAK CHECK: %s:%lu: allocated object %p with size %lu\n",
                    alloc_ptrs[i]->file, alloc_ptrs[i]->line, 
                    alloc_ptrs[i] + 1, 
                    alloc_ptrs[i]->allocation_size);
        }
    }
}


/// m61_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void m61_print_heavy_hitter_report() {
    // Your heavy-hitters code here
}
