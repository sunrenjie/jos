#include <inc/error.h>
#include <inc/stdio.h>
#include <kern/mutex.h>

#define NUM_MUTEX 8
struct Mutex {
	envid_t env_id;
	physaddr_t addr;
	int count; // count; 0 for free
};

static struct Mutex mutexes[NUM_MUTEX];

static void
mutex_dump(void) {
	int i;
	cprintf("mutex_status:\n");
	for (i = 0; i < NUM_MUTEX; i++) {
		if (mutexes[i].count > 0) {
			cprintf(" entry %d: addr=%08x, env_id=%08x, count=%d\n", i, mutexes[i].addr, mutexes[i].env_id, mutexes[i].count);
		}
	}
}

int
mutex_acquire(envid_t env_id, physaddr_t addr)
{
	int i, free = -1;
	//cprintf("mutex_acquire called with env_id=%x, addr=%x\nBefore doing anything: ", env_id, addr);
	//mutex_dump();
	for (i = 0; i < NUM_MUTEX; i++) {
		if (mutexes[i].count == 0) {
			if (free == -1)
				free = i;
		} else if (mutexes[i].addr == addr) {
			if (mutexes[i].env_id == env_id) {
				mutexes[i].count++;
				return 0;
			} else {
				return -E_MUTEX_ALREADY_ALLOCATED;
			}
		}
	}
	if (free == -1)
		return -E_MUTEX_EXHAUSTED;
	mutexes[free].env_id = env_id;
	mutexes[free].addr = addr;
	mutexes[free].count = 1;
	return 0;
}

int
mutex_release(envid_t env_id, physaddr_t addr)
{
	int i;
	//cprintf("mutex_release called with env_id=%x, addr=%x\nBefore doing anything: ", env_id, addr);
	//mutex_dump();
	for (i = 0; i < NUM_MUTEX; i++) {
		if (mutexes[i].count > 0 && mutexes[i].addr == addr &&
			mutexes[i].env_id == env_id) {
			mutexes[i].count--;
			return 0;
		}
	}
	return -E_MUTEX_NOT_ALLOCATED;
}

int
mutex_release_all(envid_t env_id)
{
	int i, freed = 0;
	//cprintf("mutex_release_all called with env_id=%x\n", env_id);
	mutex_dump();
	for (i = 0; i < NUM_MUTEX; i++) {
		if (mutexes[i].count > 0 && mutexes[i].env_id == env_id) {
			mutexes[i].count = 0;
			freed++;
		}
	}
	return freed;
}

