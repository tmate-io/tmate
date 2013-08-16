/* client.c */
/*
Copyright 2003-2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/select.h>
#include <sys/time.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif

#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>


#include "examples_common.h"
#define MAXCMD 10

static char *host;
static char *user;
static char *cmds[MAXCMD];
static struct termios terminal;

static char *pcap_file=NULL;

static char *proxycommand;

static int auth_callback(const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata) {
    (void) verify;
    (void) userdata;

    return ssh_getpass(prompt, buf, len, echo, verify);
}

struct ssh_callbacks_struct cb = {
		.auth_function=auth_callback,
		.userdata=NULL
};

static void add_cmd(char *cmd){
    int n;

    for (n = 0; (n < MAXCMD) && cmds[n] != NULL; n++);

    if (n == MAXCMD) {
        return;
    }
    cmds[n]=strdup(cmd);
}

static void usage(){
    fprintf(stderr,"Usage : ssh [options] [login@]hostname\n"
    "sample client - libssh-%s\n"
    "Options :\n"
    "  -l user : log in as user\n"
    "  -p port : connect to port\n"
    "  -d : use DSS to verify host public key\n"
    "  -r : use RSA to verify host public key\n"
#ifdef WITH_PCAP
    "  -P file : create a pcap debugging file\n"
#endif
#ifndef _WIN32
    "  -T proxycommand : command to execute as a socket proxy\n"
#endif
    		,
    ssh_version(0));
    exit(0);
}

static int opts(int argc, char **argv){
    int i;
//    for(i=0;i<argc;i++)
//        printf("%d : %s\n",i,argv[i]);
    /* insert your own arguments here */
    while((i=getopt(argc,argv,"T:P:"))!=-1){
        switch(i){
        	case 'P':
        		pcap_file=optarg;
        		break;
#ifndef _WIN32
          case 'T':
            proxycommand=optarg;
            break;
#endif
          default:
                fprintf(stderr,"unknown option %c\n",optopt);
                usage();
        }
    }
    if(optind < argc)
        host=argv[optind++];
    while(optind < argc)
        add_cmd(argv[optind++]);
    if(host==NULL)
        usage();
    return 0;
}

#ifndef HAVE_CFMAKERAW
static void cfmakeraw(struct termios *termios_p){
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
}
#endif


static void do_cleanup(int i) {
  /* unused variable */
  (void) i;

  tcsetattr(0,TCSANOW,&terminal);
}

static void do_exit(int i) {
  /* unused variable */
  (void) i;

  do_cleanup(0);
  exit(0);
}

ssh_channel chan;
int signal_delayed=0;

static void sigwindowchanged(int i){
  (void) i;
  signal_delayed=1;
}

static void setsignal(void){
    signal(SIGWINCH, sigwindowchanged);
    signal_delayed=0;
}

static void sizechanged(void){
    struct winsize win = { 0, 0, 0, 0 };
    ioctl(1, TIOCGWINSZ, &win);
    ssh_channel_change_pty_size(chan,win.ws_col, win.ws_row);
//    printf("Changed pty size\n");
    setsignal();
}

/* There are two flavors of select loop: the one based on
 * ssh_select and the one based on channel_select.
 * The ssh_select one permits you to give your own file descriptors to
 * follow. It is thus a complete select loop.
 * The second one only selects on channels. It is simplier to use
 * but doesn't permit you to fill in your own file descriptor. It is
 * more adapted if you can't use ssh_select as a main loop (because
 * you already have another main loop system).
 */

#ifdef USE_CHANNEL_SELECT

/* channel_select base main loop, with a standard select(2)
 */
static void select_loop(ssh_session session,ssh_channel channel){
    fd_set fds;
    struct timeval timeout;
    char buffer[4096];
    ssh_buffer readbuf=ssh_buffer_new();
    ssh_channel channels[2];
    int lus;
    int eof=0;
    int maxfd;
    int ret;
    while(channel){
       /* when a signal is caught, ssh_select will return
         * with SSH_EINTR, which means it should be started
         * again. It lets you handle the signal the faster you
         * can, like in this window changed example. Of course, if
         * your signal handler doesn't call libssh at all, you're
         * free to handle signals directly in sighandler.
         */
        do{
            FD_ZERO(&fds);
            if(!eof)
                FD_SET(0,&fds);
            timeout.tv_sec=30;
            timeout.tv_usec=0;
            FD_SET(ssh_get_fd(session),&fds);
            maxfd=ssh_get_fd(session)+1;
            ret=select(maxfd,&fds,NULL,NULL,&timeout);
            if(ret==EINTR)
                continue;
            if(FD_ISSET(0,&fds)){
                lus=read(0,buffer,sizeof(buffer));
                if(lus)
                    ssh_channel_write(channel,buffer,lus);
                else {
                    eof=1;
                    ssh_channel_send_eof(channel);
                }
            }
            if(FD_ISSET(ssh_get_fd(session),&fds)){
                ssh_set_fd_toread(session);
            }
            channels[0]=channel; // set the first channel we want to read from
            channels[1]=NULL;
            ret=ssh_channel_select(channels,NULL,NULL,NULL); // no specific timeout - just poll
            if(signal_delayed)
                sizechanged();
        } while (ret==EINTR || ret==SSH_EINTR);

        // we already looked for input from stdin. Now, we are looking for input from the channel

        if(channel && ssh_channel_is_closed(channel)){
            ssh_channel_free(channel);
            channel=NULL;
            channels[0]=NULL;
        }
        if(channels[0]){
            while(channel && ssh_channel_is_open(channel) && ssh_channel_poll(channel,0)>0){
                lus=channel_read_buffer(channel,readbuf,0,0);
                if(lus==-1){
                    fprintf(stderr, "Error reading channel: %s\n",
                        ssh_get_error(session));
                    return;
                }
                if(lus==0){
                    ssh_channel_free(channel);
                    channel=channels[0]=NULL;
                } else
                    if (write(1,ssh_buffer_get_begin(readbuf),lus) < 0) {
                      fprintf(stderr, "Error writing to buffer\n");
                      return;
                    }
            }
            while(channel && ssh_channel_is_open(channel) && ssh_channel_poll(channel,1)>0){ /* stderr */
                lus=channel_read_buffer(channel,readbuf,0,1);
                if(lus==-1){
                    fprintf(stderr, "Error reading channel: %s\n",
                        ssh_get_error(session));
                    return;
                }
                if(lus==0){
                    ssh_channel_free(channel);
                    channel=channels[0]=NULL;
                } else
                    if (write(2,ssh_buffer_get_begin(readbuf),lus) < 0) {
                      fprintf(stderr, "Error writing to buffer\n");
                      return;
                    }
            }
        }
        if(channel && ssh_channel_is_closed(channel)){
            ssh_channel_free(channel);
            channel=NULL;
        }
    }
    ssh_buffer_free(readbuf);
}
#else /* CHANNEL_SELECT */

static void select_loop(ssh_session session,ssh_channel channel){
	fd_set fds;
	struct timeval timeout;
	char buffer[4096];
	/* channels will be set to the channels to poll.
	 * outchannels will contain the result of the poll
	 */
	ssh_channel channels[2], outchannels[2];
	int lus;
	int eof=0;
	int maxfd;
	unsigned int r;
	int ret;
	while(channel){
		do{
			FD_ZERO(&fds);
			if(!eof)
				FD_SET(0,&fds);
			timeout.tv_sec=30;
			timeout.tv_usec=0;
			FD_SET(ssh_get_fd(session),&fds);
			maxfd=ssh_get_fd(session)+1;
			channels[0]=channel; // set the first channel we want to read from
			channels[1]=NULL;
			ret=ssh_select(channels,outchannels,maxfd,&fds,&timeout);
			if(signal_delayed)
				sizechanged();
			if(ret==EINTR)
				continue;
			if(FD_ISSET(0,&fds)){
				lus=read(0,buffer,sizeof(buffer));
				if(lus)
					ssh_channel_write(channel,buffer,lus);
				else {
					eof=1;
					ssh_channel_send_eof(channel);
				}
			}
			if(channel && ssh_channel_is_closed(channel)){
				ssh_channel_free(channel);
				channel=NULL;
				channels[0]=NULL;
			}
			if(outchannels[0]){
				while(channel && ssh_channel_is_open(channel) && (r = ssh_channel_poll(channel,0))!=0){
					lus=ssh_channel_read(channel,buffer,sizeof(buffer) > r ? r : sizeof(buffer),0);
					if(lus==-1){
						fprintf(stderr, "Error reading channel: %s\n",
								ssh_get_error(session));
						return;
					}
					if(lus==0){
						ssh_channel_free(channel);
						channel=channels[0]=NULL;
					} else
					  if (write(1,buffer,lus) < 0) {
					    fprintf(stderr, "Error writing to buffer\n");
					    return;
					  }
				}
				while(channel && ssh_channel_is_open(channel) && (r = ssh_channel_poll(channel,1))!=0){ /* stderr */
					lus=ssh_channel_read(channel,buffer,sizeof(buffer) > r ? r : sizeof(buffer),1);
					if(lus==-1){
						fprintf(stderr, "Error reading channel: %s\n",
								ssh_get_error(session));
						return;
					}
					if(lus==0){
						ssh_channel_free(channel);
						channel=channels[0]=NULL;
					} else
					  if (write(2,buffer,lus) < 0) {
					    fprintf(stderr, "Error writing to buffer\n");
					    return;
					  }
				}
			}
			if(channel && ssh_channel_is_closed(channel)){
				ssh_channel_free(channel);
				channel=NULL;
			}
		} while (ret==EINTR || ret==SSH_EINTR);

	}
}

#endif

static void shell(ssh_session session){
    ssh_channel channel;
    struct termios terminal_local;
    int interactive=isatty(0);
    channel = ssh_channel_new(session);
    if(interactive){
        tcgetattr(0,&terminal_local);
        memcpy(&terminal,&terminal_local,sizeof(struct termios));
    }
    if(ssh_channel_open_session(channel)){
        printf("error opening channel : %s\n",ssh_get_error(session));
        return;
    }
    chan=channel;
    if(interactive){
        ssh_channel_request_pty(channel);
        sizechanged();
    }
    if(ssh_channel_request_shell(channel)){
        printf("Requesting shell : %s\n",ssh_get_error(session));
        return;
    }
    if(interactive){
        cfmakeraw(&terminal_local);
        tcsetattr(0,TCSANOW,&terminal_local);
        setsignal();
    }
    signal(SIGTERM,do_cleanup);
    select_loop(session,channel);
    if(interactive)
    	do_cleanup(0);
}

static void batch_shell(ssh_session session){
    ssh_channel channel;
    char buffer[1024];
    int i,s=0;
    for(i=0;i<MAXCMD && cmds[i];++i) {
        s+=snprintf(buffer+s,sizeof(buffer)-s,"%s ",cmds[i]);
		free(cmds[i]);
		cmds[i] = NULL;
	}
    channel=ssh_channel_new(session);
    ssh_channel_open_session(channel);
    if(ssh_channel_request_exec(channel,buffer)){
        printf("error executing \"%s\" : %s\n",buffer,ssh_get_error(session));
        return;
    }
    select_loop(session,channel);
}

static int client(ssh_session session){
  int auth=0;
  char *banner;
  int state;
  if (user)
    if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0)
      return -1;
  if (ssh_options_set(session, SSH_OPTIONS_HOST ,host) < 0)
    return -1;
  if (proxycommand != NULL){
    if(ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, proxycommand))
      return -1;
  }
  ssh_options_parse_config(session, NULL);

  if(ssh_connect(session)){
      fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));
      return -1;
  }
  state=verify_knownhost(session);
  if (state != 0)
  	return -1;
  ssh_userauth_none(session, NULL);
  banner=ssh_get_issue_banner(session);
  if(banner){
      printf("%s\n",banner);
      free(banner);
  }
  auth=authenticate_console(session);
  if(auth != SSH_AUTH_SUCCESS){
  	return -1;
  }
  if(!cmds[0])
  	shell(session);
  else
  	batch_shell(session);
  return 0;
}

ssh_pcap_file pcap;
void set_pcap(ssh_session session);
void set_pcap(ssh_session session){
	if(!pcap_file)
		return;
	pcap=ssh_pcap_file_new();
	if(!pcap)
		return;
	if(ssh_pcap_file_open(pcap,pcap_file) == SSH_ERROR){
		printf("Error opening pcap file\n");
		ssh_pcap_file_free(pcap);
		pcap=NULL;
		return;
	}
	ssh_set_pcap_file(session,pcap);
}

void cleanup_pcap(void);
void cleanup_pcap(){
	if(pcap)
		ssh_pcap_file_free(pcap);
	pcap=NULL;
}

int main(int argc, char **argv){
    ssh_session session;

    session = ssh_new();

    ssh_callbacks_init(&cb);
    ssh_set_callbacks(session,&cb);

    if(ssh_options_getopt(session, &argc, argv)) {
      fprintf(stderr, "error parsing command line :%s\n",
          ssh_get_error(session));
      usage();
    }
    opts(argc,argv);
    signal(SIGTERM, do_exit);

    set_pcap(session);
    client(session);

    ssh_disconnect(session);
    ssh_free(session);
    cleanup_pcap();

    ssh_finalize();

    return 0;
}
