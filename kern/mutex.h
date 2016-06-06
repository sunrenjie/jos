#ifndef JOS_INC_MUTEX_H
#define JOS_INC_MUTEX_H
#include <inc/env.h>

int mutex_acquire(envid_t env_id, physaddr_t addr);
int mutex_release(envid_t env_id, physaddr_t addr);

#endif // !JOS_INC_MUTEX_H

