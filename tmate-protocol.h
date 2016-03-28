#ifndef TMATE_PROTOCOL_H
#define TMATE_PROTOCOL_H

enum tmate_control_out_msg_types {
	TMATE_CTL_HEADER,
	TMATE_CTL_DEAMON_OUT_MSG,
	TMATE_CTL_SNAPSHOT,
	TMATE_CTL_CLIENT_JOIN,
	TMATE_CTL_CLIENT_LEFT,
	TMATE_CTL_EXEC,
	TMATE_CTL_LATENCY,
};

/*
[TMATE_CTL_HEADER, int: ctl_proto_version, string: ip_address, string: pubkey,
                   string: session_token, string: session_token_ro, string: ssh_cmd_fmt]
	           string: client_version, int: client_protocol_version]
[TMATE_CTL_DEAMON_OUT_MSG, object: msg]
[TMATE_CTL_SNAPSHOT, [[int: pane_id, [int: cur_x, int: cur_y], int: mode,
                       [[string: line_utf8, [int: char_attr, ...]], ...], ...], ...]]
[TMATE_CTL_CLIENT_JOIN, int: client_id, string: ip_address, string: pubkey, boolean: readonly]
[TMATE_CTL_CLIENT_LEFT, int: client_id]
[TMATE_CTL_EXEC, string: username, string: ip_address, string: pubkey, string: command]
[TMATE_CTL_LATENCY, int: client_id, int: latency_ms] // client_id == -1: tmate host
*/

enum tmate_control_in_msg_types {
	TMATE_CTL_DEAMON_FWD_MSG,
	TMATE_CTL_REQUEST_SNAPSHOT,
	TMATE_CTL_PANE_KEYS,
	TMATE_CTL_RESIZE,
	TMATE_CTL_EXEC_RESPONSE,
	TMATE_CTL_RENAME_SESSION,
};

/*
[TMATE_CTL_DEAMON_FWD_MSG, object: msg]
[TMATE_CTL_REQUEST_SNAPSHOT, int: max_history_lines]
[TMATE_CTL_PANE_KEYS, int: pane_id, string: keys]
[TMATE_CTL_RESIZE, int: sx, int: sy] // sx == -1: no clients
[TMATE_CTL_EXEC_RESPONSE, int: exit_code, string: message]
[TMATE_CTL_RENAME_SESSION, string: stoken, string: stoken_ro]
*/

enum tmate_daemon_out_msg_types {
	TMATE_OUT_HEADER,
	TMATE_OUT_SYNC_LAYOUT,
	TMATE_OUT_PTY_DATA,
	TMATE_OUT_EXEC_CMD_STR,
	TMATE_OUT_FAILED_CMD,
	TMATE_OUT_STATUS,
	TMATE_OUT_SYNC_COPY_MODE,
	TMATE_OUT_WRITE_COPY_MODE,
	TMATE_OUT_FIN,
	TMATE_OUT_READY,
	TMATE_OUT_RECONNECT,
	TMATE_OUT_SNAPSHOT,
	TMATE_OUT_EXEC_CMD,
};

/*
[TMATE_OUT_HEADER, int: proto_version, string: version]
[TMATE_OUT_SYNC_LAYOUT, [int: sx, int: sy, [[int: win_id, string: win_name,
			  [[int: pane_id, int: sx, int: sy, int: xoff, int: yoff], ...],
			  int: active_pane_id], ...], int: active_win_id]
[TMATE_OUT_PTY_DATA, int: pane_id, binary: buffer]
[TMATE_OUT_EXEC_CMD_STR, string: cmd]
[TMATE_OUT_FAILED_CMD, int: client_id, string: cause]
[TMATE_OUT_STATUS, string: left, string: right]
[TMATE_OUT_SYNC_COPY_MODE, int: pane_id, [int: backing, int: oy, int: cx, int: cy,
					  [int: selx, int: sely, int: flags],
					  [int: type, string: input_prompt, string: input_str]])
                                          // Any of the array can be []
[TMATE_OUT_WRITE_COPY_MODE, int: pane_id, string: str]
[TMATE_OUT_FIN]
[TMATE_OUT_READY]
[TMATE_OUT_RECONNECT, string: reconnection_data]
[TMATE_OUT_SNAPSHOT, ...]
[TMATE_OUT_EXEC_CMD, string: cmd_name, ...string: args]
*/

enum tmate_daemon_in_msg_types {
	TMATE_IN_NOTIFY,
	TMATE_IN_LEGACY_PANE_KEY,
	TMATE_IN_RESIZE,
	TMATE_IN_EXEC_CMD_STR,
	TMATE_IN_SET_ENV,
	TMATE_IN_READY,
	TMATE_IN_PANE_KEY,
	TMATE_IN_EXEC_CMD,
};

/*
[TMATE_IN_NOTIFY, string: msg]
[TMATE_IN_PANE_KEY, int: key]
[TMATE_IN_RESIZE, int: sx, int: sy] // sx == -1: no clients
[TMATE_IN_EXEC_CMD_STR, int: client_id, string: cmd]
[TMATE_IN_SET_ENV, string: name, string: value]
[TMATE_IN_READY]
[TMATE_IN_PANE_KEY, int: pane_id, uint64 keycode] // pane_id == -1: active pane
[TMATE_IN_EXEC_CMD, int: client_id, ...string: args]
*/

#endif
