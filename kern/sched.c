#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>

static int
next_nonzero_index_in_envs(int i, int n)
{
	if (++i != n)
		return i;
	else
		return 1;
}

// Choose a user environment to run and run it.
void
sched_yield(void)
{
	// Implement simple round-robin scheduling.
	// Search through 'envs' for a runnable environment,
	// in circular fashion starting after the previously running env,
	// and switch to the first such environment found.
	// It's OK to choose the previously running env if no other env
	// is runnable.
	// But never choose envs[0], the idle environment,
	// unless NOTHING else is runnable.

	// LAB 4: Your code here.
	int i, j;
	extern struct Env *envs, *curenv;
	i = j = next_nonzero_index_in_envs(curenv ? curenv - envs : 0, NENV);
	do {
		if (envs[j].env_status == ENV_RUNNABLE) {
			env_run(&envs[j]);
			return;
		}
		j = next_nonzero_index_in_envs(j, NENV);
	} while (j != i);

	// Run the special idle environment when nothing else is runnable.
	if (envs[0].env_status == ENV_RUNNABLE)
		env_run(&envs[0]);
	else {
		cprintf("Destroyed all environments - nothing more to do!\n");
		while (1)
			monitor(NULL);
	}
}
