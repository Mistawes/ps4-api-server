#include "ps4.h"
#include "include/defines.h"
#include "include/global.h"
#include "include/kernel.h"
#include "include/sock.h"
#include "include/process.h"
#include "include/commandHandlers.h"
#define VERSION "1.1w"

#define MSG_CLIENT_CONNECED "Client [%s] connected" 
#define MSG_CLIENT_DISCONNECED "Client [%s] disconnected"
#define MSG_CLIENT_THREAD_ERROR "Error handling the client"

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

#define X86_CR0_WP (1 << 16)


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
	NOTIFY(MSG_CLIENT_CONNECED, clientIP);
	for (INFINITE)
	{
			char bufferOfClient[MAX_RECEIVE_LENGTH] = {0};
			int lenOfReceivedData = receiveFromClient(locClientSocketFd, bufferOfClient, MAX_RECEIVE_LENGTH);
			
			if (lenOfReceivedData < 1)//Client Disconnected ?
			{
				NOTIFY(MSG_CLIENT_DISCONNECED, clientIP);
				scePthreadExit(NULL);
			}

			if (bufferOfClient[0] == 'q')
			{
				closeSocket(locClientSocketFd);
				NOTIFY(MSG_CLIENT_DISCONNECED, clientIP);
				quitCommandHandler();
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

struct kpayload_args{
	uint64_t user_arg;
};

// kdump woz 'ere

int kpayload(struct thread *td, struct kpayload_args* args){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[0xF26010];
	void** got_rootvnode = (void**)&kernel_ptr[0x206D250];

	// resolve kernel functions

	//int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x286d70);
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
	
	// uart enabler
	uint64_t *securityFlags = (uint64_t *)(kernel_base+0x2001516);
	*securityFlags = *securityFlags & ~(1 << 15);

	// specters debug settings patchs
	*(char *)(kernel_base + 0x186b0a0) = 0; 
	*(char *)(kernel_base + 0x2001516) |= 0x14;
	*(char *)(kernel_base + 0x2001539) |= 1;
	*(char *)(kernel_base + 0x2001539) |= 2;
	*(char *)(kernel_base + 0x200153A) |= 1;
	*(char *)(kernel_base + 0x2001558) |= 1;	

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// debug menu full patches thanks to sealab

	*(uint32_t *)(kernel_base + 0x4CECB7) = 0;
	*(uint32_t *)(kernel_base + 0x4CFB9B) = 0;

	// Target ID Patches :)

	*(uint16_t *)(kernel_base + 0x1FE59E4) = 0x8101;
	*(uint16_t *)(kernel_base + 0X1FE5A2C) = 0x8101;
	*(uint16_t *)(kernel_base + 0x200151C) = 0x8101;

	// restore write protection

	writeCr0(cr0);

	// Say hello

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");

	printfkernel("kernel base is:0x%016llx\n", kernel_base);

	return 0;
}

// End kernel

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


int _main(struct thread *td){

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	int sRet = syscall(11,kpayload,td);

	if (!init())
		return 1;
	
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
