#include "ps4.h"
#include "include/defines.h"
#include "include/global.h"
//#include "include/kernel.h"
#include "include/sock.h"
#include "include/process.h"
#include "include/commandHandlers.h"
#define VERSION "1.1"


#define MSG_CLIENT_CONNECED "Client [%s] connected" 
#define MSG_CLIENT_DISCONNECED "Client [%s] disconnected"
#define MSG_CLIENT_THREAD_ERROR "Error handling the client"

#define Inline static inline __attribute__((always_inline))
#define	KERN_XFAST_SYSCALL 0x3095D0
#define KERN_PROCESS_ASLR 0x1BA559
#define KERN_PRISON_0 0x10399B0
#define KERN_ROOTVNODE 0x21AFA30
#define KERN_PTRACE_CHECK 0x17D2C1

#define X86_CR0_WP (1 << 16)

// Kernel
#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))
#define	CTL_KERN	1	/* "high kernel": proc, limits */
#define	KERN_PROC	14	/* struct: process entries */
#define	KERN_PROC_VMMAP	32	/* VM map entries for process */
#define	KERN_PROC_PID	1	/* by process id */
#define printfsocket(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)

int createThread(void*(func)(void*), void* args)
{
	ScePthread sceThread;
	return scePthreadCreate(&sceThread, NULL, func, args, "Clien Thread") == 0;
}

void* clientHandler(void* args)
{
	struct sockaddr_in client = *(struct sockaddr_in*)args;
	
	int locClientSocketFd = clientSockFd;
	char clientIP[16];//IPv4
	bool gotUnknownCommand = true;
	command_s *localCommands = commands;
	int localCommandsLength = lenOfCommands;
	clientIp(&client.sin_addr, clientIP);
	//NOTIFY(MSG_CLIENT_CONNECED, clientIP);
	for (INFINITE)
	{
			char bufferOfClient[MAX_RECEIVE_LENGTH] = {0};
			int lenOfReceivedData = receiveFromClient(locClientSocketFd, bufferOfClient, MAX_RECEIVE_LENGTH);
			
			if (lenOfReceivedData < 1)//Client Disconnected ?
			{
				//NOTIFY(MSG_CLIENT_DISCONNECED, clientIP);
				scePthreadExit(NULL);
			}

			if (bufferOfClient[0] == 'q')
			{
				quitCommandHandler();
				closeSocket(locClientSocketFd);
				//NOTIFY(MSG_CLIENT_DISCONNECED, clientIP);
				scePthreadExit(NULL);
			}
			for (size_t i = 0; i < localCommandsLength; i++) 
			{
		    	if(localCommands[i].commandChar == bufferOfClient[0] && localCommands[i].minLength <= lenOfReceivedData  && localCommands[i].handler != NULL)
		        {
		            localCommands[i].handler(bufferOfClient, lenOfReceivedData);
					gotUnknownCommand = false;
					break;
		        }
		    }
			if (gotUnknownCommand){
				unknownCommandHandler();
			}
			gotUnknownCommand = true;
	}
	return NULL;
}

struct auditinfo_addr {
	/*
	4    ai_auid;
	8    ai_mask;
	24    ai_termid;
	4    ai_asid;
	8    ai_flags;r
	*/
	char useless[184];
};

/*
#define printfsocket(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)
*/

unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	__asm__ __volatile__ (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	__asm__ __volatile__ (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}

struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
	uint32_t useless2;
	uint32_t useless3;
	uint32_t cr_rgid;    // real group id
	uint32_t useless4;
	void *useless5;
	void *useless6;
	void *cr_prison;     // jail(2)
	void *useless7;
	uint32_t useless8;
	void *useless9[2];
	void *useless10;
	struct auditinfo_addr useless11;
	uint32_t *cr_groups; // groups
	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
	void *fd_rdir;
	void *fd_jdir;
};

struct proc {
	char useless[64];
	struct ucred *p_ucred;
	struct filedesc *p_fd;
};

struct thread {
	void *useless;
	struct proc *td_proc;
};

struct payload_info
{
  uint64_t uaddr;
};

//int kernelPayload(struct thread *td, void* uap);

Inline uint8_t* getKernelBase() {
	uint32_t lo, hi;
	__asm__ __volatile__("rdmsr" : "=a" (lo), "=d" (hi) : "c"(0xC0000082));
	return (uint8_t*)(((uint64_t)lo | ((uint64_t)hi << 32)) - KERN_XFAST_SYSCALL);
}

struct kpayload_args
{
  void* syscall_handler;
  struct payload_info* payload_info;
};


int kpayload(struct thread *td){
//int kpayload(struct thread *td, void* uap){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;
	
	uint8_t* ptrKernel = getKernelBase();

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x3095D0];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[0x10399B0];
	void** got_rootvnode = (void**)&kernel_ptr[0x21AFA30];

	// resolve kernel functions

	//int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x14A7B0);
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x17F30);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process


	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// enable uart :)
	*(char *)(kernel_base + 0x1997BC8) = 0;

	// Disable ptrace check
	ptrKernel[KERN_PTRACE_CHECK] = 0xEB;

	// Disable process aslr
	*(uint16_t*)&ptrKernel[KERN_PROCESS_ASLR] = 0x9090;

	//Full debug settings offsets for 4.55 
	*(char *)(kernel_base + 0x1B6D086) |= 0x14;
	*(char *)(kernel_base + 0x1B6D0A9) |= 0x3;
	*(char *)(kernel_base + 0x1B6D0AA) |= 0x1;
	*(char *)(kernel_base + 0x1B6D0C8) |= 0x1;

	// debug menu full patches
	*(uint32_t *)(kernel_base + 0x4D70F7) = 0;
	*(uint32_t *)(kernel_base + 0x4D7F81) = 0;

	// restore write protection

	writeCr0(cr0);

	// Say hello and put the kernel base just for reference

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");
	printfkernel("kernel base is:0x%016llx\n", kernel_base);


	return 0;
}

/*
int init(){
	initKernel();
	initLibc();
	initNetwork();
	initSysUtil();
	initPthread();
	kexec(kernelPayload, NULL);
	if (initSockets())
	{
		NOTIFY("PS4API By BISOON STARTED v%s\n", VERSION);
		return 1;
	}
	else
	{
		NOTIFY("PS4API: Failed to run the port not available, try again later\n");
		closeSockets();
		return 0;
	}
}
*/
int _main(struct thread *td) {
//int _main(void) {

	initKernel();
	initLibc();
	initNetwork();
	initSysUtil();
	initPthread();
	initPthread();
	initSockets();
	//kexec(kernelPayload, NULL);

	// jailbreak / debug settings etc
	syscall(11,kpayload,td);

/*
	if (initSockets())
	{
		NOTIFY("PS4API By BISOON STARTED v%s\n", VERSION);
		return 1;
	}
	else
	{
		NOTIFY("PS4API: Failed to run the port not available, try again later\n");
		closeSockets();
		return 0;
	}
*/

	struct sockaddr_in clientStruct;
	int clientSocketMonitor = -1;
	for (INFINITE) 
	{
		
		clientSockFd = acceptClient(&clientStruct);
		if (clientSocketMonitor != -1)
		{
			abortSendRecv(clientSocketMonitor);
			closeSocket(clientSocketMonitor);
		}
		clientSocketMonitor = clientSockFd;
		if (!createThread(clientHandler, &clientStruct))
			NOTIFY(MSG_CLIENT_THREAD_ERROR);
	}
	closeSockets();
	return 0;
}
