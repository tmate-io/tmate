/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 Aris Adamantiadis <aris@0xbadc0de.be>
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

/* callback.h
 * This file includes the public declarations for the libssh callback mechanism
 */

#ifndef _SSH_CALLBACK_H
#define _SSH_CALLBACK_H

#include <libssh/libssh.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup libssh_callbacks The libssh callbacks
 * @ingroup libssh
 *
 * Callback which can be replaced in libssh.
 *
 * @{
 */

/** @internal
 * @brief callback to process simple codes
 * @param code value to transmit
 * @param user Userdata to pass in callback
 */
typedef void (*ssh_callback_int) (int code, void *user);

/** @internal
 * @brief callback for data received messages.
 * @param data data retrieved from the socket or stream
 * @param len number of bytes available from this stream
 * @param user user-supplied pointer sent along with all callback messages
 * @returns number of bytes processed by the callee. The remaining bytes will
 * be sent in the next callback message, when more data is available.
 */
typedef int (*ssh_callback_data) (const void *data, size_t len, void *user);

typedef void (*ssh_callback_int_int) (int code, int errno_code, void *user);

typedef int (*ssh_message_callback) (ssh_session, ssh_message message, void *user);
typedef int (*ssh_channel_callback_int) (ssh_channel channel, int code, void *user);
typedef int (*ssh_channel_callback_data) (ssh_channel channel, int code, void *data, size_t len, void *user);

/**
 * @brief SSH log callback. All logging messages will go through this callback
 * @param session Current session handler
 * @param priority Priority of the log, the smaller being the more important
 * @param message the actual message
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_log_callback) (ssh_session session, int priority,
    const char *message, void *userdata);

/**
 * @brief SSH Connection status callback.
 * @param session Current session handler
 * @param status Percentage of connection status, going from 0.0 to 1.0
 * once connection is done.
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_status_callback) (ssh_session session, float status,
		void *userdata);

/**
 * @brief SSH global request callback. All global request will go through this
 * callback.
 * @param session Current session handler
 * @param message the actual message
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_global_request_callback) (ssh_session session,
                                        ssh_message message, void *userdata);

/**
 * The structure to replace libssh functions with appropriate callbacks.
 */
struct ssh_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
  /**
   * This functions will be called if e.g. a keyphrase is needed.
   */
  ssh_auth_callback auth_function;
  /**
   * This function will be called each time a loggable event happens.
   */
  ssh_log_callback log_function;
  /**
   * This function gets called during connection time to indicate the
   * percentage of connection steps completed.
   */
  void (*connect_status_function)(void *userdata, float status);
  /**
   * This function will be called each time a global request is received.
   */
  ssh_global_request_callback global_request_function;
};
typedef struct ssh_callbacks_struct *ssh_callbacks;

/**
 * These are the callbacks exported by the socket structure
 * They are called by the socket module when a socket event appears
 */
struct ssh_socket_callbacks_struct {
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
	/**
	 * This function will be called each time data appears on socket. The data
	 * not consumed will appear on the next data event.
	 */
  ssh_callback_data data;
  /** This function will be called each time a controlflow state changes, i.e.
   * the socket is available for reading or writing.
   */
  ssh_callback_int controlflow;
  /** This function will be called each time an exception appears on socket. An
   * exception can be a socket problem (timeout, ...) or an end-of-file.
   */
  ssh_callback_int_int exception;
  /** This function is called when the ssh_socket_connect was used on the socket
   * on nonblocking state, and the connection successed.
   */
  ssh_callback_int_int connected;
};
typedef struct ssh_socket_callbacks_struct *ssh_socket_callbacks;

#define SSH_SOCKET_FLOW_WRITEWILLBLOCK 1
#define SSH_SOCKET_FLOW_WRITEWONTBLOCK 2

#define SSH_SOCKET_EXCEPTION_EOF 	     1
#define SSH_SOCKET_EXCEPTION_ERROR     2

#define SSH_SOCKET_CONNECTED_OK 			1
#define SSH_SOCKET_CONNECTED_ERROR 		2
#define SSH_SOCKET_CONNECTED_TIMEOUT 	3

/**
 * @brief Initializes an ssh_callbacks_struct
 * A call to this macro is mandatory when you have set a new
 * ssh_callback_struct structure. Its goal is to maintain the binary
 * compatibility with future versions of libssh as the structure
 * evolves with time.
 */
#define ssh_callbacks_init(p) do {\
	(p)->size=sizeof(*(p)); \
} while(0);

/**
 * @internal
 * @brief tests if a callback can be called without crash
 *  verifies that the struct size if big enough
 *  verifies that the callback pointer exists
 * @param p callback pointer
 * @param c callback name
 * @returns nonzero if callback can be called
 */
#define ssh_callbacks_exists(p,c) (\
  (p != NULL) && ( (char *)&((p)-> c) < (char *)(p) + (p)->size ) && \
  ((p)-> c != NULL) \
  )

/** @brief Prototype for a packet callback, to be called when a new packet arrives
 * @param session The current session of the packet
 * @param type packet type (see ssh2.h)
 * @param packet buffer containing the packet, excluding size, type and padding fields
 * @param user user argument to the callback
 * and are called each time a packet shows up
 * @returns SSH_PACKET_USED Packet was parsed and used
 * @returns SSH_PACKET_NOT_USED Packet was not used or understood, processing must continue
 */
typedef int (*ssh_packet_callback) (ssh_session session, uint8_t type, ssh_buffer packet, void *user);

/** return values for a ssh_packet_callback */
/** Packet was used and should not be parsed by another callback */
#define SSH_PACKET_USED 1
/** Packet was not used and should be passed to any other callback
 * available */
#define SSH_PACKET_NOT_USED 2


/** @brief This macro declares a packet callback handler
 * @code
 * SSH_PACKET_CALLBACK(mycallback){
 * ...
 * }
 * @endcode
 */
#define SSH_PACKET_CALLBACK(name) \
	int name (ssh_session session, uint8_t type, ssh_buffer packet, void *user)

struct ssh_packet_callbacks_struct {
	/** Index of the first packet type being handled */
	uint8_t start;
	/** Number of packets being handled by this callback struct */
	uint8_t n_callbacks;
	/** A pointer to n_callbacks packet callbacks */
	ssh_packet_callback *callbacks;
  /**
   * User-provided data. User is free to set anything he wants here
   */
	void *user;
};

typedef struct ssh_packet_callbacks_struct *ssh_packet_callbacks;

/**
 * @brief Set the session callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for auth, logging and status.
 *
 * @code
 * struct ssh_callbacks_struct cb = {
 *   .userdata = data,
 *   .auth_function = my_auth_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_callbacks(session, &cb);
 * @endcode
 *
 * @param  session      The session to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
LIBSSH_API int ssh_set_callbacks(ssh_session session, ssh_callbacks cb);

/**
 * @brief SSH channel data callback. Called when data is available on a channel
 * @param session Current session handler
 * @param channel the actual channel
 * @param data the data that has been read on the channel
 * @param len the length of the data
 * @param is_stderr is 0 for stdout or 1 for stderr
 * @param userdata Userdata to be passed to the callback function.
 */
typedef int (*ssh_channel_data_callback) (ssh_session session,
                                           ssh_channel channel,
                                           void *data,
                                           uint32_t len,
                                           int is_stderr,
                                           void *userdata);

/**
 * @brief SSH channel eof callback. Called when a channel receives EOF
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_eof_callback) (ssh_session session,
                                           ssh_channel channel,
                                           void *userdata);

/**
 * @brief SSH channel close callback. Called when a channel is closed by remote peer
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_close_callback) (ssh_session session,
                                            ssh_channel channel,
                                            void *userdata);

/**
 * @brief SSH channel signal callback. Called when a channel has received a signal
 * @param session Current session handler
 * @param channel the actual channel
 * @param signal the signal name (without the SIG prefix)
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_signal_callback) (ssh_session session,
                                            ssh_channel channel,
                                            const char *signal,
                                            void *userdata);

/**
 * @brief SSH channel exit status callback. Called when a channel has received an exit status
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_exit_status_callback) (ssh_session session,
                                            ssh_channel channel,
                                            int exit_status,
                                            void *userdata);

/**
 * @brief SSH channel exit signal callback. Called when a channel has received an exit signal
 * @param session Current session handler
 * @param channel the actual channel
 * @param signal the signal name (without the SIG prefix)
 * @param core a boolean telling wether a core has been dumped or not
 * @param errmsg the description of the exception
 * @param lang the language of the description (format: RFC 3066)
 * @param userdata Userdata to be passed to the callback function.
 */
typedef void (*ssh_channel_exit_signal_callback) (ssh_session session,
                                            ssh_channel channel,
                                            const char *signal,
                                            int core,
                                            const char *errmsg,
                                            const char *lang,
                                            void *userdata);

struct ssh_channel_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
  /**
   * This functions will be called when there is data available.
   */
  ssh_channel_data_callback channel_data_function;
  /**
   * This functions will be called when the channel has received an EOF.
   */
  ssh_channel_eof_callback channel_eof_function;
  /**
   * This functions will be called when the channel has been closed by remote
   */
  ssh_channel_close_callback channel_close_function;
  /**
   * This functions will be called when a signal has been received
   */
  ssh_channel_signal_callback channel_signal_function;
  /**
   * This functions will be called when an exit status has been received
   */
  ssh_channel_exit_status_callback channel_exit_status_function;
  /**
   * This functions will be called when an exit signal has been received
   */
  ssh_channel_exit_signal_callback channel_exit_signal_function;
};
typedef struct ssh_channel_callbacks_struct *ssh_channel_callbacks;

/**
 * @brief Set the channel callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for channel data and exceptions
 *
 * @code
 * struct ssh_channel_callbacks_struct cb = {
 *   .userdata = data,
 *   .channel_data = my_channel_data_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_channel_callbacks(channel, &cb);
 * @endcode
 *
 * @param  channel      The channel to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
LIBSSH_API int ssh_set_channel_callbacks(ssh_channel channel,
                                         ssh_channel_callbacks cb);

/** @} */

/** @group libssh_threads
 * @{
 */

typedef int (*ssh_thread_callback) (void **lock);

typedef unsigned long (*ssh_thread_id_callback) (void);
struct ssh_threads_callbacks_struct {
	const char *type;
  ssh_thread_callback mutex_init;
  ssh_thread_callback mutex_destroy;
  ssh_thread_callback mutex_lock;
  ssh_thread_callback mutex_unlock;
  ssh_thread_id_callback thread_id;
};

/**
 * @brief sets the thread callbacks necessary if your program is using
 * libssh in a multithreaded fashion. This function must be called first,
 * outside of any threading context (in your main() for instance), before
 * ssh_init().
 * @param cb pointer to a ssh_threads_callbacks_struct structure, which contains
 * the different callbacks to be set.
 * @see ssh_threads_callbacks_struct
 * @see SSH_THREADS_PTHREAD
 */
LIBSSH_API int ssh_threads_set_callbacks(struct ssh_threads_callbacks_struct
    *cb);

/**
 * @brief returns a pointer on the pthread threads callbacks, to be used with
 * ssh_threads_set_callbacks.
 * @warning you have to link with the library ssh_threads.
 * @see ssh_threads_set_callbacks
 */
LIBSSH_API struct ssh_threads_callbacks_struct *ssh_threads_get_pthread(void);

/**
 * @brief returns a pointer on the noop threads callbacks, to be used with
 * ssh_threads_set_callbacks. These callbacks do nothing and are being used by
 * default.
 * @see ssh_threads_set_callbacks
 */
LIBSSH_API struct ssh_threads_callbacks_struct *ssh_threads_get_noop(void);

/** @} */
#ifdef __cplusplus
}
#endif

#endif /*_SSH_CALLBACK_H */

/* @} */
