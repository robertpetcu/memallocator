// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"
#include "printf.h"
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
struct block_meta *base;
#define initial_size (128 * 1024)
int inWork;

// Function to split a block if it is large enough
struct block_meta  *split_block(struct block_meta *block, size_t size)
{
    size = ALIGN(size); // Align size to fit
    if (block == NULL || size > block->size)
        return NULL;
    if (block->size < ALIGN(sizeof(struct block_meta)) + size)
        return block;
    
    // Create a new block from the remaining space
    struct block_meta *new_block = (struct block_meta *)((char *)block + ALIGN(sizeof(struct block_meta)) + size);
    new_block->status = STATUS_FREE;
    new_block->next = block->next;
    new_block->prev = block;
    new_block->size = block->size - ALIGN(sizeof(struct block_meta)) - size;
    block->next = new_block;
    block->size = size;
    return block;
}

// Function to coalesce adjacent free blocks into one
void coallesce_block(struct block_meta *block)
{
    struct block_meta *next = block->next;
    struct block_meta *prev = block->prev;
    
    // Coalesce with next block if it's free
    if (next && next->status == STATUS_FREE) {
        block->size = block->size + ALIGN(sizeof(struct block_meta)) + next->size;
        block->next = next->next;
        if (next->next)
            next->next->prev = block;
    }
    
    // Coalesce with previous block if it's free
    if (prev && prev->status == STATUS_FREE) {  
        prev->size = prev->size + ALIGN(sizeof(struct block_meta)) + block->size;
        prev->next = block->next;
        if (block->next)
            block->next->prev = prev;
    }
}

// Function to find the best fitting free block
struct block_meta *find_best_block(size_t size)
{
    struct block_meta *best_block = NULL;
    struct block_meta *current_block = base;
    size = ALIGN(size);

    // Search for a block that is large enough
    while (current_block != NULL) {
        if (current_block->status == STATUS_FREE && current_block->size >= size ) {
            best_block = current_block;
            break;
        }
        current_block = current_block->next;
    }

    // Find the best block with minimal wasted space
    if (best_block == NULL) return NULL;
    while (current_block != NULL) {
        if (current_block->status == STATUS_FREE && current_block->size >= size) {
            if (current_block->size - size  < best_block->size - size) {
                best_block = current_block;
            }
        }
        current_block = current_block->next;
    }
    return best_block;
}

// Function to find the last block in the list
struct block_meta *last_block(struct block_meta *block)
{
    if (!block) {
        return NULL;
    }
    while (block->next) {
        block = block->next;
    }
    return block;
}

// Function to allocate memory at the start (preallocate)
void heap_preallocation(void)
{
    base = (struct block_meta *)sbrk(initial_size); // Allocate space
    base->size = initial_size;
    base->status = STATUS_FREE;
    base->next = NULL;
    base->prev = NULL;
}

// Helper function to initialize a block for mmap allocation
void *mmap_allocation(void *ptr , size_t size , size_t status)
{
    struct block_meta *block = (struct block_meta *)ptr;
    block->size = size;
    block->status = status;
    block->next = NULL;
}

// Memory allocation function (malloc)
void *os_malloc(size_t size)
{
    if (size == 0) return NULL; // Return NULL if size is 0

    if (inWork == 1) {
        struct block_meta *block;
        if (size + ALIGN(sizeof(struct block_meta)) >= 4096) {
            // Use mmap for large allocations
            block = mmap(NULL, size + ALIGN(sizeof(struct block_meta)), PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20, -1, 0);
            mmap_allocation(block, size, STATUS_MAPPED);
            memset((void *)((char *)(block) + ALIGN(sizeof(struct block_meta))), 0, size); // Initialize to 0
            return (void *)((char *)(block) + ALIGN(sizeof(struct block_meta)));
        }
        inWork = 0;
    }

    size = ALIGN(size); // Align requested size
    if (size + ALIGN(sizeof(struct block_meta)) < initial_size && base == NULL) {
        heap_preallocation(); // Preallocate if no base exists
    }

    struct block_meta *block;
    if (size + ALIGN(sizeof(struct block_meta)) >= initial_size) {
        // Use mmap for large allocations
        block = mmap(NULL, size + ALIGN(sizeof(struct block_meta)), PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20, -1, 0);
        mmap_allocation(block, size, STATUS_MAPPED);
        return (void *)((char *)(block) + ALIGN(sizeof(struct block_meta)));
    }

    block = find_best_block(size); // Find the best fitting free block
    if (block) {
        if (block->size - ALIGN(sizeof(struct block_meta)) - size > ALIGN(1)) {
            block = split_block(block, size); // Split the block if it's too large
        }
        block->status = STATUS_ALLOC; // Mark the block as allocated
        return (void *)((char *)(block) + ALIGN(sizeof(struct block_meta)));
    }

    // If no suitable block, extend the heap
    block = last_block(base);
    if (block && block->status == STATUS_FREE) {
        sbrk(size - block->size); // Extend the heap size
        block->size = size;
        block->status = STATUS_ALLOC; // Mark as allocated
        return (void *)((char *)(block) + ALIGN(sizeof(struct block_meta)));
    } else {
        struct block_meta *aux;
        aux = sbrk(size + ALIGN(sizeof(struct block_meta))); // Allocate new block
        aux->size = size;
        aux->status = STATUS_ALLOC; // Mark as allocated
        aux->prev = block;
        aux->next = NULL;
        block->next = aux;
        return (void *)((char *)(aux) + ALIGN(sizeof(struct block_meta)));
    }
}

// Memory deallocation function (free)
void os_free(void *ptr)
{
    if (ptr == 0) {
        return; // Do nothing if pointer is NULL
    }
    struct block_meta *block = (struct block_meta *)((char *)ptr - ALIGN(sizeof(struct block_meta)));
    if (block->status == STATUS_MAPPED) {
        munmap(block, block->size + ALIGN(sizeof(struct block_meta))); // Unmap if mmaped
        return;
    }
    if (block->status == STATUS_ALLOC) {
        block->status = STATUS_FREE; // Mark the block as free
        coallesce_block(block); // Try to coalesce adjacent free blocks
    }
}

// Calloc implementation (allocates and zeroes memory)
void *os_calloc(size_t nmemb, size_t size)
{
    if (nmemb == 0 || size == 0) {
        return NULL; // Return NULL if no memory requested
    }
    inWork = 1;
    size = ALIGN(nmemb * size); // Align total size
    void *ptr = os_malloc(size); // Allocate memory
    if (ptr) {
        memset(ptr, 0, size); // Initialize to 0
    }
    return ptr;
}
