// User-level IPC library routines

#include <inc/lib.h>
// Receive a value via IPC and return it.
// If 'pg' is nonnull, then any page sent by the sender will be mapped at
//	that address.
// If 'fromenv' is nonnull, then store the IPC sender's envid in *fromenv.
// If 'perm' is nonnull, then store the IPC sender's page permission in *perm
//	(this is nonzero iff a page was successfully transferred to 'pg').
// If the system call fails, then store 0 in *fromenv and *perm (if
//	they're nonnull) and return the error.
//
// Hint:
//   Use 'env' to discover the value and who sent it.
//   If 'pg' is null, pass sys_ipc_recv a value that it will understand
//   as meaning "no page".  (Zero is not the right value.)
uint32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
	// LAB 4: Your code here.
	int r;
	void *va;
	if (pg)
		va = pg;
	else
		va = (void *)UTOP; // an address signaling no page receiving
	if ((r = sys_ipc_recv(va)) < 0) {
		if (from_env_store)
			*from_env_store = 0;
		if (perm_store)
			*perm_store = 0;
		return r;
	} else {
		if (from_env_store)
			*from_env_store = env->env_ipc_from;
		if (perm_store)
			*perm_store = env->env_ipc_perm;
		return env->env_ipc_value;
	}
}

// Send 'val' (and 'pg' with 'perm', assuming 'pg' is nonnull) to 'toenv'.
// This function keeps trying until it succeeds.
// It should panic() on any error other than -E_IPC_NOT_RECV.
//
// Hint:
//   Use sys_yield() to be CPU-friendly.
//   If 'pg' is null, pass sys_ipc_recv a value that it will understand
//   as meaning "no page".  (Zero is not the right value.)
void
ipc_send(envid_t to_env, uint32_t val, void *pg, int perm)
{
	// LAB 4: Your code here.
	int r;
	void *va;
	va = pg ? pg : (void *)UTOP;
	while (1) {
		r = sys_ipc_try_send(to_env, val, va, perm);
		if (r == 1)
			return;
		else if (r == 0) {
			if (va >= (void *)UTOP) // page is fake?
				return;
			// Variants of ipc_send() that are more tolerant may
			// choose to ignore the cases when page sending is
			// intended but does not succeed.
			panic("ipc_send: the target did not receive page at va %08x.\n", va);
		} else if (r != -E_IPC_NOT_RECV)
			panic("ipc_send: error sending: %e\n", r);
		sys_yield();
	}
}

