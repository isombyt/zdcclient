/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  main control for zdclient.
 *
 *        Version:  1.0
 *        Created:  07/06/2009 03:53:22 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOYPT (PT), pentie@gmail.com
 *        Company:  http://apt-blog.co.cc
 *
 * =====================================================================================
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "zdclient.h"

#define LOCKFILE "/var/run/zdclient.pid"        /* 锁文件 */

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

static void signal_interrupted (int signo);

extern pcap_t      *handle;
extern int          exit_flag;

int                 lockfile;                  /* 锁文件的描述字 */

void
flock_reg ()
{
    char buf[16];
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    fl.l_pid = getpid();
 
    //阻塞式的加锁
    if (fcntl (lockfile, F_SETLKW, &fl) < 0){
        perror ("fcntl_reg");
        exit(1);
    }
 
    //把pid写入锁文件
    assert (0 == ftruncate (lockfile, 0) );    
    sprintf (buf, "%ld", (long)getpid());
    assert (-1 != write (lockfile, buf, strlen(buf) + 1));
}


void
daemon_init(void)
{
	pid_t	pid;
    int     fd0;

	if ( (pid = fork()) < 0)
	    perror ("Fork");
	else if (pid != 0) {
        fprintf(stdout, "&&Info: ZDClient Forked background with PID: [%d]\n\n", pid);
		exit(0);
    }
	setsid();		/* become session leader */
	assert (0 == chdir("/tmp"));		/* change working directory */
	umask(0);		/* clear our file mode creation mask */
    flock_reg ();

    fd0 = open ("/dev/null", O_RDWR);
    dup2 (fd0, STDIN_FILENO);
    dup2 (fd0, STDERR_FILENO);
    dup2 (fd0, STDOUT_FILENO);
    close (fd0);
}


int 
program_running_check()
{
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
 
    //尝试获得文件锁
    if (fcntl (lockfile, F_GETLK, &fl) < 0){
        perror ("fcntl_get");
        exit(1);
    }

    if (exit_flag) {
        if (fl.l_type != F_UNLCK) {
            if ( kill (fl.l_pid, SIGINT) == -1 )
                perror("kill");
            fprintf (stdout, "&&Info: Kill Signal Sent to PID %d.\n", fl.l_pid);
        }
        else 
            fprintf (stderr, "&&Info: NO ZDClient Running.\n");
        exit (EXIT_FAILURE);
    }

    //没有锁，则给文件加锁，否则返回锁着文件的进程pid
    if (fl.l_type == F_UNLCK) {
        flock_reg ();
        return 0;
    }

    return fl.l_pid;
}

static void
signal_interrupted (int signo)
{
    fprintf(stdout,"\n&&Info: USER Interrupted. \n");
    send_eap_packet(EAPOL_LOGOFF);
    pcap_breakloop (handle);
}


int main(int argc, char **argv)
{
    //初始化并解释程序的启动参数
    init_arguments (&argc, &argv);

    //打开锁文件
    lockfile = open (LOCKFILE, O_RDWR | O_CREAT , LOCKMODE);
    if (lockfile < 0){
        perror ("Lockfile");
        exit(1);
    }

    //检测程序的副本运行（文件锁）
    int ins_pid;
    if ( (ins_pid = program_running_check ()) ) {
        fprintf(stderr,"@@ERROR: ZDClient Already "
                            "Running with PID %d\n", ins_pid);
        exit(EXIT_FAILURE);
    }

    //初始化用户信息
    init_info();

    //初始化设备，打开网卡，获得Mac、IP等信息
    init_device();

    //初始化发送帧的缓冲区
    init_frames ();

    signal (SIGINT, signal_interrupted);
    signal (SIGTERM, signal_interrupted);    
    show_local_info();

    //发出第一个上线请求报文
    send_eap_packet (EAPOL_START);

    //进入回呼循环。以后的动作由回呼函数get_packet驱动，
    //直到pcap_break_loop执行，退出程序。
	pcap_loop (handle, -2, get_packet, NULL);   /* main loop */
    pcap_close (handle);
    return 0;
}




