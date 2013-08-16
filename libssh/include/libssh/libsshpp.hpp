/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LIBSSHPP_HPP_
#define LIBSSHPP_HPP_

/**
 * @defgroup ssh_cpp The libssh C++ wrapper
 *
 * The C++ bindings for libssh are completely embedded in a single .hpp file, and
 * this for two reasons:
 * - C++ is hard to keep binary compatible, C is easy. We try to keep libssh C version
 *   as much as possible binary compatible between releases, while this would be hard for
 *   C++. If you compile your program with these headers, you will only link to the C version
 *   of libssh which will be kept ABI compatible. No need to recompile your C++ program
 *   each time a new binary-compatible version of libssh is out
 * - Most of the functions in this file are really short and are probably worth the "inline"
 *   linking mode, which the compiler can decide to do in some case. There would be nearly no
 *   performance penalty of using the wrapper rather than native calls.
 *
 * Please visit the documentation of ssh::Session and ssh::Channel
 * @see ssh::Session
 * @see ssh::Channel
 *
 * If you wish not to use C++ exceptions, please define SSH_NO_CPP_EXCEPTIONS:
 * @code
 * #define SSH_NO_CPP_EXCEPTIONS
 * #include <libssh/libsshpp.hpp>
 * @endcode
 * All functions will then return SSH_ERROR in case of error.
 * @{
 */

/* do not use deprecated functions */
#define LIBSSH_LEGACY_0_4

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

namespace ssh {

class Channel;
/** Some people do not like C++ exceptions. With this define, we give
 * the choice to use or not exceptions.
 * @brief if defined, disable C++ exceptions for libssh c++ wrapper
 */
#ifndef SSH_NO_CPP_EXCEPTIONS

/** @brief This class describes a SSH Exception object. This object can be thrown
 * by several SSH functions that interact with the network, and may fail because of
 * socket, protocol or memory errors.
 */
class SshException{
public:
  SshException(ssh_session csession){
    code=ssh_get_error_code(csession);
    description=std::string(ssh_get_error(csession));
  }
  SshException(const SshException &e){
    code=e.code;
    description=e.description;
  }
  /** @brief returns the Error code
   * @returns SSH_FATAL Fatal error happened (not recoverable)
   * @returns SSH_REQUEST_DENIED Request was denied by remote host
   * @see ssh_get_error_code
   */
  int getCode(){
    return code;
  }
  /** @brief returns the error message of the last exception
   * @returns pointer to a c string containing the description of error
   * @see ssh_get_error
   */
  std::string getError(){
    return description;
  }
private:
  int code;
  std::string description;
};

/** @internal
 * @brief Macro to throw exception if there was an error
 */
#define ssh_throw(x) if((x)==SSH_ERROR) throw SshException(getCSession())
#define ssh_throw_null(CSession,x) if((x)==NULL) throw SshException(CSession)
#define void_throwable void
#define return_throwable return

#else

/* No exception at all. All functions will return an error code instead
 * of an exception
 */
#define ssh_throw(x) if((x)==SSH_ERROR) return SSH_ERROR
#define ssh_throw_null(CSession,x) if((x)==NULL) return NULL
#define void_throwable int
#define return_throwable return SSH_OK
#endif

/**
 * The ssh::Session class contains the state of a SSH connection.
 */
class Session {
  friend class Channel;
public:
  Session(){
    c_session=ssh_new();
  }
  ~Session(){
    ssh_free(c_session);
    c_session=NULL;
  }
  /** @brief sets an SSH session options
   * @param type Type of option
   * @param option cstring containing the value of option
   * @throws SshException on error
   * @see ssh_options_set
   */
  void_throwable setOption(enum ssh_options_e type, const char *option){
    ssh_throw(ssh_options_set(c_session,type,option));
    return_throwable;
  }
  /** @brief sets an SSH session options
   * @param type Type of option
   * @param option long integer containing the value of option
   * @throws SshException on error
   * @see ssh_options_set
   */
  void_throwable setOption(enum ssh_options_e type, long int option){
    ssh_throw(ssh_options_set(c_session,type,&option));
    return_throwable;
  }
  /** @brief sets an SSH session options
   * @param type Type of option
   * @param option void pointer containing the value of option
   * @throws SshException on error
   * @see ssh_options_set
   */
  void_throwable setOption(enum ssh_options_e type, void *option){
    ssh_throw(ssh_options_set(c_session,type,option));
    return_throwable;
  }
  /** @brief connects to the remote host
   * @throws SshException on error
   * @see ssh_connect
   */
  void_throwable connect(){
    int ret=ssh_connect(c_session);
    ssh_throw(ret);
    return_throwable;
  }
  /** @brief Authenticates automatically using public key
   * @throws SshException on error
   * @returns SSH_AUTH_SUCCESS, SSH_AUTH_PARTIAL, SSH_AUTH_DENIED
   * @see ssh_userauth_autopubkey
   */
  int userauthPublickeyAuto(void){
    int ret=ssh_userauth_publickey_auto(c_session, NULL, NULL);
    ssh_throw(ret);
    return ret;
  }
  /** @brief Authenticates using the "none" method. Prefer using autopubkey if
   * possible.
   * @throws SshException on error
   * @returns SSH_AUTH_SUCCESS, SSH_AUTH_PARTIAL, SSH_AUTH_DENIED
   * @see ssh_userauth_none
   * @see Session::userauthAutoPubkey
   */
  int userauthNone(){
    int ret=ssh_userauth_none(c_session,NULL);
    ssh_throw(ret);
    return ret;
  }
  /** @brief Authenticates using the password method.
   * @param[in] password password to use for authentication
   * @throws SshException on error
   * @returns SSH_AUTH_SUCCESS, SSH_AUTH_PARTIAL, SSH_AUTH_DENIED
   * @see ssh_userauth_password
   */
  int userauthPassword(const char *password){
    int ret=ssh_userauth_password(c_session,NULL,password);
    ssh_throw(ret);
    return ret;
  }
  /** @brief Try to authenticate using the publickey method.
   * @param[in] pubkey public key to use for authentication
   * @throws SshException on error
   * @returns SSH_AUTH_SUCCESS if the pubkey is accepted,
   * @returns SSH_AUTH_DENIED if the pubkey is denied
   * @see ssh_userauth_try_pubkey
   */
  int userauthTryPublickey(ssh_key pubkey){
    int ret=ssh_userauth_try_publickey(c_session, NULL, pubkey);
    ssh_throw(ret);
    return ret;
  }
  /** @brief Authenticates using the publickey method.
   * @param[in] privkey private key to use for authentication
   * @throws SshException on error
   * @returns SSH_AUTH_SUCCESS, SSH_AUTH_PARTIAL, SSH_AUTH_DENIED
   * @see ssh_userauth_pubkey
   */
  int userauthPublickey(ssh_key privkey){
    int ret=ssh_userauth_publickey(c_session, NULL, privkey);
    ssh_throw(ret);
    return ret;
  }
  int userauthPrivatekeyFile(const char *filename,
      const char *passphrase);
  /** @brief Returns the available authentication methods from the server
   * @throws SshException on error
   * @returns Bitfield of available methods.
   * @see ssh_userauth_list
   */
  int getAuthList(){
    int ret=ssh_userauth_list(c_session, NULL);
    ssh_throw(ret);
    return ret;
  }
  /** @brief Disconnects from the SSH server and closes connection
   * @see ssh_disconnect
   */
  void disconnect(){
    ssh_disconnect(c_session);
  }
  /** @brief Returns the disconnect message from the server, if any
   * @returns pointer to the message, or NULL. Do not attempt to free
   * the pointer.
   */
  const char *getDisconnectMessage(){
    const char *msg=ssh_get_disconnect_message(c_session);
    return msg;
  }
  /** @internal
   * @brief gets error message
   */
  const char *getError(){
    return ssh_get_error(c_session);
  }
  /** @internal
   * @brief returns error code
   */
  int getErrorCode(){
    return ssh_get_error_code(c_session);
  }
  /** @brief returns the file descriptor used for the communication
   * @returns the file descriptor
   * @warning if a proxycommand is used, this function will only return
   * one of the two file descriptors being used
   * @see ssh_get_fd
   */
  socket_t getSocket(){
    return ssh_get_fd(c_session);
  }
  /** @brief gets the Issue banner from the ssh server
   * @returns the issue banner. This is generally a MOTD from server
   * @see ssh_get_issue_banner
   */
  std::string getIssueBanner(){
    char *banner=ssh_get_issue_banner(c_session);
    std::string ret= std::string(banner);
    ::free(banner);
    return ret;
  }
  /** @brief returns the OpenSSH version (server) if possible
   * @returns openssh version code
   * @see ssh_get_openssh_version
   */
  int getOpensshVersion(){
    return ssh_get_openssh_version(c_session);
  }
  /** @brief returns the version of the SSH protocol being used
   * @returns the SSH protocol version
   * @see ssh_get_version
   */
  int getVersion(){
    return ssh_get_version(c_session);
  }
  /** @brief verifies that the server is known
   * @throws SshException on error
   * @returns Integer value depending on the knowledge of the
   * server key
   * @see ssh_is_server_known
   */
  int isServerKnown(){
    int ret=ssh_is_server_known(c_session);
    ssh_throw(ret);
    return ret;
  }
  void log(int priority, const char *format, ...){
    char buffer[1024];
    va_list va;

    va_start(va, format);
    vsnprintf(buffer, sizeof(buffer), format, va);
    va_end(va);
    _ssh_log(priority, "libsshpp", "%s", buffer);
  }

  /** @brief copies options from a session to another
   * @throws SshException on error
   * @see ssh_options_copy
   */
  void_throwable optionsCopy(const Session &source){
    ssh_throw(ssh_options_copy(source.c_session,&c_session));
    return_throwable;
  }
  /** @brief parses a configuration file for options
   * @throws SshException on error
   * @param[in] file configuration file name
   * @see ssh_options_parse_config
   */
  void_throwable optionsParseConfig(const char *file){
    ssh_throw(ssh_options_parse_config(c_session,file));
    return_throwable;
  }
  /** @brief silently disconnect from remote host
   * @see ssh_silent_disconnect
   */
  void silentDisconnect(){
    ssh_silent_disconnect(c_session);
  }
  /** @brief Writes the known host file with current
   * host key
   * @throws SshException on error
   * @see ssh_write_knownhost
   */
  int writeKnownhost(){
    int ret = ssh_write_knownhost(c_session);
    ssh_throw(ret);
    return ret;
  }

  /** @brief accept an incoming forward connection
   * @param[in] timeout_ms timeout for waiting, in ms
   * @returns new Channel pointer on the forward connection
   * @returns NULL in case of error
   * @warning you have to delete this pointer after use
   * @see ssh_channel_forward_accept
   * @see Session::listenForward
   */
  Channel *acceptForward(int timeout_ms);
  /* acceptForward is implemented later in this file */

  void_throwable cancelForward(const char *address, int port){
    int err=ssh_forward_cancel(c_session, address, port);
    ssh_throw(err);
    return_throwable;
  }

  void_throwable listenForward(const char *address, int port,
      int &boundport){
    int err=ssh_forward_listen(c_session, address, port, &boundport);
    ssh_throw(err);
    return_throwable;
  }

private:
  ssh_session c_session;
  ssh_session getCSession(){
    return c_session;
  }
  /* No copy constructor, no = operator */
  Session(const Session &);
  Session& operator=(const Session &);
};

/** @brief the ssh::Channel class describes the state of an SSH
 * channel.
 * @see ssh_channel
 */
class Channel {
  friend class Session;
public:
  Channel(Session &session){
    channel=ssh_channel_new(session.getCSession());
    this->session=&session;
  }
  ~Channel(){
    ssh_channel_free(channel);
    channel=NULL;
  }

  /** @brief accept an incoming X11 connection
   * @param[in] timeout_ms timeout for waiting, in ms
   * @returns new Channel pointer on the X11 connection
   * @returns NULL in case of error
   * @warning you have to delete this pointer after use
   * @see ssh_channel_accept_x11
   * @see Channel::requestX11
   */
  Channel *acceptX11(int timeout_ms){
    ssh_channel x11chan = ssh_channel_accept_x11(channel,timeout_ms);
    ssh_throw_null(getCSession(),x11chan);
    Channel *newchan = new Channel(getSession(),x11chan);
    return newchan;
  }
  /** @brief change the size of a pseudoterminal
   * @param[in] cols number of columns
   * @param[in] rows number of rows
   * @throws SshException on error
   * @see ssh_channel_change_pty_size
   */
  void_throwable changePtySize(int cols, int rows){
    int err=ssh_channel_change_pty_size(channel,cols,rows);
    ssh_throw(err);
    return_throwable;
  }

  /** @brief closes a channel
   * @throws SshException on error
   * @see ssh_channel_close
   */
  void_throwable close(){
    ssh_throw(ssh_channel_close(channel));
    return_throwable;
  }

  int getExitStatus(){
    return ssh_channel_get_exit_status(channel);
  }
  Session &getSession(){
    return *session;
  }
  /** @brief returns true if channel is in closed state
   * @see ssh_channel_is_closed
   */
  bool isClosed(){
    return ssh_channel_is_closed(channel) != 0;
  }
  /** @brief returns true if channel is in EOF state
   * @see ssh_channel_is_eof
   */
  bool isEof(){
    return ssh_channel_is_eof(channel) != 0;
  }
  /** @brief returns true if channel is in open state
   * @see ssh_channel_is_open
   */
  bool isOpen(){
    return ssh_channel_is_open(channel) != 0;
  }
  int openForward(const char *remotehost, int remoteport,
      const char *sourcehost=NULL, int localport=0){
    int err=ssh_channel_open_forward(channel,remotehost,remoteport,
        sourcehost, localport);
    ssh_throw(err);
    return err;
  }
  /* TODO: completely remove this ? */
  void_throwable openSession(){
    int err=ssh_channel_open_session(channel);
    ssh_throw(err);
    return_throwable;
  }
  int poll(bool is_stderr=false){
    int err=ssh_channel_poll(channel,is_stderr);
    ssh_throw(err);
    return err;
  }
  int read(void *dest, size_t count, bool is_stderr=false){
    int err;
    /* handle int overflow */
    if(count > 0x7fffffff)
      count = 0x7fffffff;
    err=ssh_channel_read(channel,dest,count,is_stderr);
    ssh_throw(err);
    return err;
  }
  int readNonblocking(void *dest, size_t count, bool is_stderr=false){
    int err;
    /* handle int overflow */
    if(count > 0x7fffffff)
      count = 0x7fffffff;
    err=ssh_channel_read_nonblocking(channel,dest,count,is_stderr);
    ssh_throw(err);
    return err;
  }
  void_throwable requestEnv(const char *name, const char *value){
    int err=ssh_channel_request_env(channel,name,value);
    ssh_throw(err);
    return_throwable;
  }

  void_throwable requestExec(const char *cmd){
    int err=ssh_channel_request_exec(channel,cmd);
    ssh_throw(err);
    return_throwable;
  }
  void_throwable requestPty(const char *term=NULL, int cols=0, int rows=0){
    int err;
    if(term != NULL && cols != 0 && rows != 0)
      err=ssh_channel_request_pty_size(channel,term,cols,rows);
    else
      err=ssh_channel_request_pty(channel);
    ssh_throw(err);
    return_throwable;
  }

  void_throwable requestShell(){
    int err=ssh_channel_request_shell(channel);
    ssh_throw(err);
    return_throwable;
  }
  void_throwable requestSendSignal(const char *signum){
    int err=ssh_channel_request_send_signal(channel, signum);
    ssh_throw(err);
    return_throwable;
  }
  void_throwable requestSubsystem(const char *subsystem){
    int err=ssh_channel_request_subsystem(channel,subsystem);
    ssh_throw(err);
    return_throwable;
  }
  int requestX11(bool single_connection,
      const char *protocol, const char *cookie, int screen_number){
    int err=ssh_channel_request_x11(channel,single_connection,
        protocol, cookie, screen_number);
    ssh_throw(err);
    return err;
  }
  void_throwable sendEof(){
    int err=ssh_channel_send_eof(channel);
    ssh_throw(err);
    return_throwable;
  }
  /** @brief Writes on a channel
   * @param data data to write.
   * @param len number of bytes to write.
   * @param is_stderr write should be done on the stderr channel (server only)
   * @returns number of bytes written
   * @throws SshException in case of error
   * @see channel_write
   * @see channel_write_stderr
   */
  int write(const void *data, size_t len, bool is_stderr=false){
    int ret;
    if(is_stderr){
      ret=ssh_channel_write_stderr(channel,data,len);
    } else {
      ret=ssh_channel_write(channel,data,len);
    }
    ssh_throw(ret);
    return ret;
  }
private:
  ssh_session getCSession(){
    return session->getCSession();
  }
  Channel (Session &session, ssh_channel c_channel){
    this->channel=c_channel;
    this->session=&session;
  }
  Session *session;
  ssh_channel channel;
  /* No copy and no = operator */
  Channel(const Channel &);
  Channel &operator=(const Channel &);
};


/* This code cannot be put inline due to references to Channel */
Channel *Session::acceptForward(int timeout_ms){
    ssh_channel forward = ssh_forward_accept(c_session,
        timeout_ms);
    ssh_throw_null(c_session,forward);
    Channel *newchan = new Channel(*this,forward);
    return newchan;
  }

} // namespace ssh

/** @} */
#endif /* LIBSSHPP_HPP_ */
