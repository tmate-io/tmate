/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013 by Aris Adamantiadis <aris@badcode.be>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gssapi/gssapi.h>

#include <libssh/gssapi.h>
#include <libssh/libssh.h>
#include <libssh/ssh2.h>
#include <libssh/buffer.h>
#include <libssh/crypto.h>
#include <libssh/callbacks.h>
#include <libssh/string.h>
#include <libssh/server.h>

/** current state of an GSSAPI authentication */
enum ssh_gssapi_state_e {
    SSH_GSSAPI_STATE_NONE, /* no status */
    SSH_GSSAPI_STATE_RCV_TOKEN, /* Expecting a token */
    SSH_GSSAPI_STATE_RCV_MIC, /* Expecting a MIC */
};

struct ssh_gssapi_struct{
    enum ssh_gssapi_state_e state; /* current state */
    struct gss_OID_desc_struct mech; /* mechanism being elected for auth */
    gss_cred_id_t server_creds; /* credentials of server */
    gss_cred_id_t client_creds; /* creds of the client */
    gss_ctx_id_t ctx; /* the authentication context */
    gss_name_t client_name; /* Identity of the client */
    char *user; /* username of client */
    char *canonic_user; /* canonic form of the client's username */
    char *service; /* name of the service */
    struct {
        gss_name_t server_name; /* identity of server */
        gss_OID oid; /* mech being used for authentication */
        gss_cred_id_t client_deleg_creds; /* delegated creds (const, not freeable) */
    } client;
};


/** @internal
 * @initializes a gssapi context for authentication
 */
static int ssh_gssapi_init(ssh_session session){
    if (session->gssapi != NULL)
        return SSH_OK;
    session->gssapi = malloc(sizeof(struct ssh_gssapi_struct));
    if(!session->gssapi){
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    ZERO_STRUCTP(session->gssapi);
    session->gssapi->server_creds = GSS_C_NO_CREDENTIAL;
    session->gssapi->client_creds = GSS_C_NO_CREDENTIAL;
    session->gssapi->ctx = GSS_C_NO_CONTEXT;
    session->gssapi->state = SSH_GSSAPI_STATE_NONE;
    return SSH_OK;
}

/** @internal
 * @frees a gssapi context
 */
static void ssh_gssapi_free(ssh_session session){
    OM_uint32 min;
    if (session->gssapi == NULL)
        return;
    if (session->gssapi->mech.elements)
        SAFE_FREE(session->gssapi->mech.elements);
    if (session->gssapi->user)
        SAFE_FREE(session->gssapi->user);
    if (session->gssapi->server_creds)
        gss_release_cred(&min,&session->gssapi->server_creds);
    SAFE_FREE(session->gssapi);
}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token){
#ifdef WITH_SERVER
    if(session->server)
        return ssh_packet_userauth_gssapi_token_server(session, type, packet, user);
#endif
    return ssh_packet_userauth_gssapi_token_client(session, type, packet, user);
}
#ifdef WITH_SERVER

/** @internal
 * @brief sends a SSH_MSG_USERAUTH_GSSAPI_RESPONSE packet
 * @param[in] oid the OID that was selected for authentication
 */
static int ssh_gssapi_send_response(ssh_session session, ssh_string oid){
    if (buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_GSSAPI_RESPONSE) < 0 ||
            buffer_add_ssh_string(session->out_buffer,oid) < 0) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    packet_send(session);
    SSH_LOG(SSH_LOG_PACKET,
            "Sent SSH_MSG_USERAUTH_GSSAPI_RESPONSE");
    return SSH_OK;
}

#endif /* WITH_SERVER */

static void ssh_gssapi_log_error(int verb, const char *msg, int maj_stat){
    gss_buffer_desc buffer;
    OM_uint32 dummy, message_context;
    gss_display_status(&dummy,maj_stat,GSS_C_GSS_CODE, GSS_C_NO_OID, &message_context, &buffer);
    SSH_LOG(verb, "GSSAPI(%s): %s", msg, (const char *)buffer.value);
}

#ifdef WITH_SERVER

/** @internal
 * @brief handles an user authentication using GSSAPI
 */
int ssh_gssapi_handle_userauth(ssh_session session, const char *user, uint32_t n_oid, ssh_string *oids){
    char service_name[]="host";
    gss_buffer_desc name_buf;
    gss_name_t server_name; /* local server fqdn */
    OM_uint32 maj_stat, min_stat;
    unsigned int i;
    char *ptr;
    gss_OID_set supported; /* oids supported by server */
    gss_OID_set both_supported; /* oids supported by both client and server */
    gss_OID_set selected; /* oid selected for authentication */
    int present=0;
    int oid_count=0;
    struct gss_OID_desc_struct oid;
    int rc;

    if (ssh_callbacks_exists(session->server_callbacks, gssapi_select_oid_function)){
        ssh_string oid_s = session->server_callbacks->gssapi_select_oid_function(session,
                user, n_oid, oids,
                session->server_callbacks->userdata);
        if (oid_s != NULL){
            if (ssh_gssapi_init(session) == SSH_ERROR)
                return SSH_ERROR;
            session->gssapi->state = SSH_GSSAPI_STATE_RCV_TOKEN;
            rc = ssh_gssapi_send_response(session, oid_s);
            ssh_string_free(oid_s);
            return rc;
        } else {
            return ssh_auth_reply_default(session,0);
        }
    }
    gss_create_empty_oid_set(&min_stat, &both_supported);

    maj_stat = gss_indicate_mechs(&min_stat, &supported);
    for (i=0; i < supported->count; ++i){
        ptr = ssh_get_hexa(supported->elements[i].elements, supported->elements[i].length);
        SSH_LOG(SSH_LOG_DEBUG, "Supported mech %d: %s\n", i, ptr);
        free(ptr);
    }

    for (i=0 ; i< n_oid ; ++i){
        unsigned char *oid_s = (unsigned char *) ssh_string_data(oids[i]);
        size_t len = ssh_string_len(oids[i]);
        if(len < 2 || oid_s[0] != SSH_OID_TAG || ((size_t)oid_s[1]) != len - 2){
            SSH_LOG(SSH_LOG_WARNING,"GSSAPI: received invalid OID");
            continue;
        }
        oid.elements = &oid_s[2];
        oid.length = len - 2;
        gss_test_oid_set_member(&min_stat,&oid,supported,&present);
        if(present){
            gss_add_oid_set_member(&min_stat,&oid,&both_supported);
            oid_count++;
        }
    }
    gss_release_oid_set(&min_stat, &supported);
    if (oid_count == 0){
        SSH_LOG(SSH_LOG_PROTOCOL,"GSSAPI: no OID match");
        ssh_auth_reply_default(session, 0);
        gss_release_oid_set(&min_stat, &both_supported);
        return SSH_OK;
    }
    /* from now we have room for context */
    if (ssh_gssapi_init(session) == SSH_ERROR)
        return SSH_ERROR;

    name_buf.value = service_name;
    name_buf.length = strlen(name_buf.value) + 1;
    maj_stat = gss_import_name(&min_stat, &name_buf,
            (gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &server_name);
    if (maj_stat != GSS_S_COMPLETE) {
        SSH_LOG(0, "importing name %d, %d", maj_stat, min_stat);
        ssh_gssapi_log_error(0, "importing name", maj_stat);
        return -1;
    }

    maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
            both_supported, GSS_C_ACCEPT,
            &session->gssapi->server_creds, &selected, NULL);
    gss_release_name(&min_stat, &server_name);
    gss_release_oid_set(&min_stat, &both_supported);

    if (maj_stat != GSS_S_COMPLETE) {
        SSH_LOG(0, "error acquiring credentials %d, %d", maj_stat, min_stat);
        ssh_gssapi_log_error(0, "acquiring creds", maj_stat);
        ssh_auth_reply_default(session,0);
        return SSH_ERROR;
    }

    SSH_LOG(0, "acquiring credentials %d, %d", maj_stat, min_stat);

    /* finding which OID from client we selected */
    for (i=0 ; i< n_oid ; ++i){
        unsigned char *oid_s = (unsigned char *) ssh_string_data(oids[i]);
        size_t len = ssh_string_len(oids[i]);
        if(len < 2 || oid_s[0] != SSH_OID_TAG || ((size_t)oid_s[1]) != len - 2){
            SSH_LOG(SSH_LOG_WARNING,"GSSAPI: received invalid OID");
            continue;
        }
        oid.elements = &oid_s[2];
        oid.length = len - 2;
        gss_test_oid_set_member(&min_stat,&oid,selected,&present);
        if(present){
            SSH_LOG(SSH_LOG_PACKET, "Selected oid %d", i);
            break;
        }
    }
    session->gssapi->mech.length = oid.length;
    session->gssapi->mech.elements = malloc(oid.length);
    if (session->gssapi->mech.elements == NULL){
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    memcpy(session->gssapi->mech.elements, oid.elements, oid.length);
    gss_release_oid_set(&min_stat, &selected);
    session->gssapi->user = strdup(user);
    session->gssapi->service = service_name;
    session->gssapi->state = SSH_GSSAPI_STATE_RCV_TOKEN;
    return ssh_gssapi_send_response(session, oids[i]);
}

static char *ssh_gssapi_name_to_char(gss_name_t name){
    gss_buffer_desc buffer;
    OM_uint32 maj_stat, min_stat;
    char *ptr;
    maj_stat = gss_display_name(&min_stat, name, &buffer, NULL);
    ssh_gssapi_log_error(0, "converting name", maj_stat);
    ptr=malloc(buffer.length + 1);
    memcpy(ptr, buffer.value, buffer.length);
    ptr[buffer.length] = '\0';
    gss_release_buffer(&min_stat, &buffer);
    return ptr;

}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_server){
    ssh_string token;
    char *hexa;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token, output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name = GSS_C_NO_NAME;
    OM_uint32 ret_flags=0;
    gss_channel_bindings_t input_bindings=GSS_C_NO_CHANNEL_BINDINGS;
    int rc;

    (void)user;
    (void)type;

    SSH_LOG(SSH_LOG_PACKET,"Received SSH_MSG_USERAUTH_GSSAPI_TOKEN");
    if (!session->gssapi || session->gssapi->state != SSH_GSSAPI_STATE_RCV_TOKEN){
        ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_USERAUTH_GSSAPI_TOKEN in invalid state");
        return SSH_PACKET_USED;
    }
    token = buffer_get_ssh_string(packet);

    if (token == NULL){
        ssh_set_error(session, SSH_REQUEST_DENIED, "ssh_packet_userauth_gssapi_token: invalid packet");
        return SSH_PACKET_USED;
    }

    if (ssh_callbacks_exists(session->server_callbacks, gssapi_accept_sec_ctx_function)){
        ssh_string out_token=NULL;
        rc = session->server_callbacks->gssapi_accept_sec_ctx_function(session,
                token, &out_token, session->server_callbacks->userdata);
        if (rc == SSH_ERROR){
            ssh_auth_reply_default(session, 0);
            ssh_gssapi_free(session);
            session->gssapi=NULL;
            return SSH_PACKET_USED;
        }
        if (ssh_string_len(out_token) != 0){
            rc = buffer_add_u8(session->out_buffer,
                               SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
            if (rc < 0) {
                ssh_set_error_oom(session);
                return SSH_PACKET_USED;
            }
            rc = buffer_add_ssh_string(session->out_buffer, out_token);
            if (rc < 0) {
                ssh_set_error_oom(session);
                return SSH_PACKET_USED;
            }
            packet_send(session);
            ssh_string_free(out_token);
        } else {
            session->gssapi->state = SSH_GSSAPI_STATE_RCV_MIC;
        }
        return SSH_PACKET_USED;
    }
    hexa = ssh_get_hexa(ssh_string_data(token),ssh_string_len(token));
    SSH_LOG(SSH_LOG_PACKET, "GSSAPI Token : %s",hexa);
    SAFE_FREE(hexa);
    input_token.length = ssh_string_len(token);
    input_token.value = ssh_string_data(token);

    maj_stat = gss_accept_sec_context(&min_stat, &session->gssapi->ctx, session->gssapi->server_creds,
            &input_token, input_bindings, &client_name, NULL /*mech_oid*/, &output_token, &ret_flags,
            NULL /*time*/, &session->gssapi->client_creds);
    ssh_gssapi_log_error(0, "accepting token", maj_stat);
    ssh_string_free(token);
    if (client_name != GSS_C_NO_NAME){
        session->gssapi->client_name = client_name;
        session->gssapi->canonic_user = ssh_gssapi_name_to_char(client_name);
    }
    if (GSS_ERROR(maj_stat)){
        ssh_gssapi_log_error(SSH_LOG_PROTOCOL, "Gssapi error", maj_stat);
        ssh_auth_reply_default(session,0);
        ssh_gssapi_free(session);
        session->gssapi=NULL;
        return SSH_PACKET_USED;
    }

    if (output_token.length != 0){
        hexa = ssh_get_hexa(output_token.value, output_token.length);
        SSH_LOG(SSH_LOG_PACKET, "GSSAPI: sending token %s",hexa);
        SAFE_FREE(hexa);
        token = ssh_string_new(output_token.length);
        ssh_string_fill(token, output_token.value, output_token.length);
        buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
        buffer_add_ssh_string(session->out_buffer,token);
        packet_send(session);
        ssh_string_free(token);
    }
    if(maj_stat == GSS_S_COMPLETE){
        session->gssapi->state = SSH_GSSAPI_STATE_RCV_MIC;
    }
    return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */

static ssh_buffer ssh_gssapi_build_mic(ssh_session session){
    ssh_buffer mic_buffer;
    ssh_string str;
    int rc;

    str = ssh_string_new(session->current_crypto->digest_len);
    if (str == NULL) {
        return NULL;
    }
    ssh_string_fill(str, session->current_crypto->session_id,
                    session->current_crypto->digest_len);

    mic_buffer = ssh_buffer_new();
    if (mic_buffer == NULL) {
        ssh_string_free(str);
        return NULL;
    }

    rc = buffer_add_ssh_string(mic_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        ssh_buffer_free(mic_buffer);
        return NULL;
    }

    rc = buffer_add_u8(mic_buffer, SSH2_MSG_USERAUTH_REQUEST);
    if (rc < 0) {
        ssh_buffer_free(mic_buffer);
        return NULL;
    }

    str = ssh_string_from_char(session->gssapi->user);
    if (str == NULL) {
        ssh_buffer_free(mic_buffer);
        return NULL;
    }

    rc = buffer_add_ssh_string(mic_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        ssh_buffer_free(mic_buffer);
        return NULL;
    }

    str = ssh_string_from_char("ssh-connection");
    if (str == NULL) {
        ssh_buffer_free(mic_buffer);
        return NULL;
    }
    rc = buffer_add_ssh_string(mic_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        ssh_buffer_free(mic_buffer);
        return NULL;
    }

    str = ssh_string_from_char("gssapi-with-mic");
    if (str == NULL) {
        ssh_buffer_free(mic_buffer);
        return NULL;
    }

    rc = buffer_add_ssh_string(mic_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        ssh_buffer_free(mic_buffer);
        return NULL;
    }

    return mic_buffer;
}

#ifdef WITH_SERVER

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_mic)
{
    ssh_string mic_token;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc mic_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mic_token_buf = GSS_C_EMPTY_BUFFER;
    ssh_buffer mic_buffer = NULL;

    (void)user;
    (void)type;

    SSH_LOG(SSH_LOG_PACKET,"Received SSH_MSG_USERAUTH_GSSAPI_MIC");
    mic_token = buffer_get_ssh_string(packet);
    if (mic_token == NULL) {
        ssh_set_error(session, SSH_FATAL, "Missing MIC in packet");
        goto error;
    }
    if (session->gssapi == NULL
        || session->gssapi->state != SSH_GSSAPI_STATE_RCV_MIC) {
        ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_USERAUTH_GSSAPI_MIC in invalid state");
        goto error;
    }

    mic_buffer = ssh_gssapi_build_mic(session);
    if (mic_buffer == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }
    if (ssh_callbacks_exists(session->server_callbacks, gssapi_verify_mic_function)){
        int rc = session->server_callbacks->gssapi_verify_mic_function(session, mic_token,
                ssh_buffer_get_begin(mic_buffer), ssh_buffer_get_len(mic_buffer),
                session->server_callbacks->userdata);
        if (rc != SSH_OK) {
            goto error;
        }
    } else {
        mic_buf.length = ssh_buffer_get_len(mic_buffer);
        mic_buf.value = ssh_buffer_get_begin(mic_buffer);
        mic_token_buf.length = ssh_string_len(mic_token);
        mic_token_buf.value = ssh_string_data(mic_token);

        maj_stat = gss_verify_mic(&min_stat, session->gssapi->ctx, &mic_buf, &mic_token_buf, NULL);
        ssh_gssapi_log_error(0, "verifying MIC", maj_stat);
        ssh_gssapi_log_error(0, "verifying MIC (min stat)", min_stat);
        if (maj_stat == GSS_S_DEFECTIVE_TOKEN || GSS_ERROR(maj_stat)) {
            goto error;
        }
    }

    if (ssh_callbacks_exists(session->server_callbacks, auth_gssapi_mic_function)){
        switch(session->server_callbacks->auth_gssapi_mic_function(session,
                    session->gssapi->user, session->gssapi->canonic_user,
                    session->server_callbacks->userdata)){
            case SSH_AUTH_SUCCESS:
                ssh_auth_reply_success(session, 0);
                break;
            case SSH_AUTH_PARTIAL:
                ssh_auth_reply_success(session, 1);
                break;
            default:
                ssh_auth_reply_default(session, 0);
                break;
        }
    }

    goto end;

error:
    ssh_auth_reply_default(session,0);

end:
    ssh_gssapi_free(session);
    if (mic_buffer != NULL) {
        ssh_buffer_free(mic_buffer);
    }
    if (mic_token != NULL) {
        ssh_string_free(mic_token);
    }

    return SSH_PACKET_USED;
}

/** @brief returns the client credentials of the connected client.
 * If the client has given a forwardable token, the SSH server will
 * retrieve it.
 * @returns gssapi credentials handle.
 * @returns NULL if no forwardable token is available.
 */
ssh_gssapi_creds ssh_gssapi_get_creds(ssh_session session){
    if (!session || !session->gssapi || session->gssapi->client_creds == GSS_C_NO_CREDENTIAL)
        return NULL;
    return (ssh_gssapi_creds)session->gssapi->client_creds;
}

/**
 * @brief Set the forwadable ticket to be given to the server for authentication.
 *
 * @param[in] creds gssapi credentials handle.
 */
void ssh_gssapi_set_creds(ssh_session session, const ssh_gssapi_creds creds)
{
    if (session == NULL) {
        return;
    }
    if (session->gssapi == NULL) {
        ssh_gssapi_init(session);
        if (session->gssapi == NULL) {
            return;
        }
    }

    session->gssapi->client.client_deleg_creds = (gss_cred_id_t)creds;
}

#endif /* SERVER */

static int ssh_gssapi_send_auth_mic(ssh_session session, ssh_string *oid_set, int n_oid){
    ssh_string str;
    int rc;
    int i;
    rc = buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_REQUEST);
    if (rc < 0) {
        goto fail;
    }
    /* username */
    str = ssh_string_from_char(session->opts.username);
    if (str == NULL) {
        goto fail;
    }
    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }
    /* service */
    str = ssh_string_from_char("ssh-connection");
    if (str == NULL) {
        goto fail;
    }
    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }
    /* method */
    str = ssh_string_from_char("gssapi-with-mic");
    if (str == NULL) {
        goto fail;
    }
    rc = buffer_add_ssh_string(session->out_buffer, str);
    ssh_string_free(str);
    if (rc < 0) {
        goto fail;
    }

    rc = buffer_add_u32(session->out_buffer, htonl(n_oid));
    if (rc < 0) {
        goto fail;
    }

    for (i=0; i<n_oid; ++i){
        rc = buffer_add_ssh_string(session->out_buffer, oid_set[i]);
        if (rc < 0) {
            goto fail;
        }
    }

    session->auth_state = SSH_AUTH_STATE_GSSAPI_REQUEST_SENT;
    return packet_send(session);
fail:
    buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

/** @brief returns the OIDs of the mechs that work with both
 * hostname and username
 */
static int ssh_gssapi_match(ssh_session session, char *hostname, char *username, gss_OID_set *valid_oids, int deleg){
    gss_buffer_desc host_namebuf, user_namebuf;
    gss_name_t host_name, user_name;
    OM_uint32 maj_stat, min_stat;
    gss_OID_set supported;
    gss_OID oid;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t client_creds = GSS_C_NO_CREDENTIAL;
    unsigned int i;
    char *ptr;
    char hostname_buf[256];


    gss_create_empty_oid_set(&min_stat, valid_oids);
    maj_stat = gss_indicate_mechs(&min_stat, &supported);
    for (i=0; i < supported->count; ++i){
        ptr=ssh_get_hexa(supported->elements[i].elements, supported->elements[i].length);
        SSH_LOG(SSH_LOG_DEBUG, "GSSAPI oid supported %d : %s\n",i, ptr);
        SAFE_FREE(ptr);
    }

    user_namebuf.value = username;
    user_namebuf.length = strlen(username) + 1;
    maj_stat = gss_import_name(&min_stat, &user_namebuf,
            (gss_OID) GSS_C_NT_USER_NAME, &user_name);
    if (maj_stat != GSS_S_COMPLETE) {
        SSH_LOG(SSH_LOG_DEBUG, "importing name %d, %d", maj_stat, min_stat);
        ssh_gssapi_log_error(SSH_LOG_DEBUG, "importing name", maj_stat);
        return -1;
    }

    snprintf(hostname_buf, sizeof(hostname_buf),"host@%s", hostname);
    host_namebuf.value = hostname_buf;
    host_namebuf.length = strlen(hostname_buf) + 1;
    maj_stat = gss_import_name(&min_stat, &host_namebuf,
            (gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &host_name);
    if (maj_stat != GSS_S_COMPLETE) {
        SSH_LOG(0, "importing name %d, %d", maj_stat, min_stat);
        ssh_gssapi_log_error(0, "importing name", maj_stat);
        return -1;
    }

    ssh_gssapi_init(session);
    session->gssapi->client_name = user_name;
    session->gssapi->client.server_name = host_name;
    session->gssapi->user = strdup(username);
    for (i=0; i<supported->count; ++i){
        oid = &supported->elements[i];
        maj_stat = gss_init_sec_context(&min_stat,
                session->gssapi->client.client_deleg_creds, &ctx, host_name, oid,
                GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | (deleg ? GSS_C_DELEG_FLAG : 0),
                0, NULL, &input_token, NULL, &output_token, NULL, NULL);
        if (!GSS_ERROR(maj_stat)){
            gss_OID_set tmp;
            if (session->gssapi->client.client_deleg_creds != GSS_C_NO_CREDENTIAL){
                /* we know the oid is ok since init_sec_context worked */
                gss_add_oid_set_member(&min_stat, oid, valid_oids);
                SSH_LOG(SSH_LOG_PROTOCOL, "Matched oid %u for server (with forwarding)", i);
            } else {
                gss_create_empty_oid_set(&min_stat, &tmp);
                gss_add_oid_set_member(&min_stat, oid, &tmp);
                maj_stat = gss_acquire_cred(&min_stat, user_name, 0,
                        tmp, GSS_C_INITIATE,
                        &client_creds, NULL, NULL);
                gss_release_oid_set(&min_stat, &tmp);
                if (!GSS_ERROR(maj_stat)){
                    gss_release_cred(&min_stat, &client_creds);
                    gss_add_oid_set_member(&min_stat,oid,valid_oids);
                    SSH_LOG(SSH_LOG_PROTOCOL, "Matched oid %u for server", i);
                }
            }
        }
        gss_delete_sec_context(&min_stat,&ctx, &output_token);
        ctx = GSS_C_NO_CONTEXT;
    }

    return SSH_OK;
}

/**
 * @brief launches a gssapi-with-mic auth request
 * @returns SSH_AUTH_ERROR:   A serious error happened\n
 *          SSH_AUTH_DENIED:  Authentication failed : use another method\n
 *          SSH_AUTH_AGAIN:   In nonblocking mode, you've got to call this again
 *                            later.
 */
int ssh_gssapi_auth_mic(ssh_session session){
    int i;
    gss_OID_set selected; /* oid selected for authentication */
    ssh_string *oids;
    int rc;
    int n_oids = 0;

    if (ssh_gssapi_init(session) == SSH_ERROR)
        return SSH_AUTH_ERROR;


    SSH_LOG(SSH_LOG_PROTOCOL, "Authenticating with gssapi to host %s with user %s",
            session->opts.host, session->opts.username);
    rc = ssh_gssapi_match(session,session->opts.host, session->opts.username, &selected, 0);
    if (rc == SSH_ERROR)
        return SSH_AUTH_DENIED;

    n_oids = selected->count;
    SSH_LOG(SSH_LOG_PROTOCOL, "Sending %d oids", n_oids);

    oids = calloc(n_oids, sizeof(ssh_string));

    for (i=0; i<n_oids; ++i){
        oids[i] = ssh_string_new(selected->elements[i].length + 2);
        ((unsigned char *)oids[i]->data)[0] = SSH_OID_TAG;
        ((unsigned char *)oids[i]->data)[1] = selected->elements[i].length;
        memcpy((unsigned char *)oids[i]->data + 2, selected->elements[i].elements,
                selected->elements[i].length);
    }

    rc = ssh_gssapi_send_auth_mic(session, oids, n_oids);
    for (i = 0; i < n_oids; i++) {
        ssh_string_free(oids[i]);
    }
    free(oids);
    if (rc != SSH_ERROR) {
        return SSH_AUTH_AGAIN;
    }

    return SSH_AUTH_ERROR;
}

static gss_OID ssh_gssapi_oid_from_string(ssh_string oid_s){
    gss_OID ret = malloc(sizeof (gss_OID_desc));
    unsigned char *data = ssh_string_data(oid_s);
    size_t len = ssh_string_len(oid_s);
    if(len > 256 || len <= 2){
        SAFE_FREE(ret);
        return NULL;
    }
    if(data[0] != SSH_OID_TAG || data[1] != len - 2){
        SAFE_FREE(ret);
        return NULL;
    }
    ret->elements = malloc(len - 2);
    memcpy(ret->elements, &data[2], len-2);
    ret->length = len-2;
    return ret;
}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_response){
    ssh_string oid_s;
    gss_OID oid;
    gss_uint32 maj_stat, min_stat;
    int deleg = 0;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_OID_set tmp;
    char *hexa;
    ssh_string token;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    (void)type;
    (void)user;

    SSH_LOG(SSH_LOG_PACKET, "Received SSH_USERAUTH_GSSAPI_RESPONSE");
    if (session->auth_state != SSH_AUTH_STATE_GSSAPI_REQUEST_SENT){
        ssh_set_error(session, SSH_FATAL, "Invalid state in ssh_packet_userauth_gssapi_response");
        return SSH_PACKET_USED;
    }
    oid_s = buffer_get_ssh_string(packet);
    if (!oid_s){
        ssh_set_error(session, SSH_FATAL, "Missing OID");
        return SSH_PACKET_USED;
    }
    oid = ssh_gssapi_oid_from_string(oid_s);
    ssh_string_free(oid_s);
    if (!oid) {
        ssh_set_error(session, SSH_FATAL, "Invalid OID");
        return SSH_PACKET_USED;
    }
    if (session->gssapi->client.client_deleg_creds != GSS_C_NO_CREDENTIAL)
        creds = session->gssapi->client.client_deleg_creds;
    if (creds == GSS_C_NO_CREDENTIAL){
        gss_create_empty_oid_set(&min_stat, &tmp);
        gss_add_oid_set_member(&min_stat, oid, &tmp);
        maj_stat = gss_acquire_cred(&min_stat, session->gssapi->client_name, 0,
                tmp, GSS_C_INITIATE,
                &session->gssapi->client_creds, NULL, NULL);
        gss_release_oid_set(&min_stat, &tmp);
        if (GSS_ERROR(maj_stat)){
            ssh_gssapi_log_error(SSH_LOG_WARNING,"Error acquiring credentials",maj_stat);
            return SSH_PACKET_USED;
        }
    }
    /* prepare the first TOKEN response */
    maj_stat = gss_init_sec_context(&min_stat,
            creds, &session->gssapi->ctx, session->gssapi->client.server_name, oid,
            GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | (deleg ? GSS_C_DELEG_FLAG : 0),
            0, NULL, &input_token, NULL, &output_token, NULL, NULL);
    if(GSS_ERROR(maj_stat)){
        ssh_gssapi_log_error(SSH_LOG_WARNING, "Initializing gssapi context", maj_stat);
        return SSH_PACKET_USED;
    }
    if (output_token.length != 0){
        hexa = ssh_get_hexa(output_token.value, output_token.length);
        SSH_LOG(SSH_LOG_PACKET, "GSSAPI: sending token %s",hexa);
        SAFE_FREE(hexa);
        token = ssh_string_new(output_token.length);
        ssh_string_fill(token, output_token.value, output_token.length);
        buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
        buffer_add_ssh_string(session->out_buffer,token);
        packet_send(session);
        ssh_string_free(token);
        session->auth_state = SSH_AUTH_STATE_GSSAPI_TOKEN;
    }
    session->gssapi->client.oid = oid;
    return SSH_PACKET_USED;
}

static int ssh_gssapi_send_mic(ssh_session session){
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc mic_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mic_token_buf = GSS_C_EMPTY_BUFFER;
    ssh_buffer mic_buffer;
    int rc;

    SSH_LOG(SSH_LOG_PACKET,"Sending SSH_MSG_USERAUTH_GSSAPI_MIC");

    mic_buffer = ssh_gssapi_build_mic(session);
    if (mic_buffer == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    mic_buf.length = ssh_buffer_get_len(mic_buffer);
    mic_buf.value = ssh_buffer_get_begin(mic_buffer);

    maj_stat = gss_get_mic(&min_stat,session->gssapi->ctx, GSS_C_QOP_DEFAULT, &mic_buf, &mic_token_buf);
    if (GSS_ERROR(maj_stat)){
        ssh_buffer_free(mic_buffer);
        ssh_gssapi_log_error(0, "generating MIC", maj_stat);
        return SSH_ERROR;
    }

    rc = buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_GSSAPI_MIC);
    if (rc < 0) {
        ssh_buffer_free(mic_buffer);
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    rc = buffer_add_u32(session->out_buffer, htonl(mic_token_buf.length));
    if (rc < 0) {
        ssh_buffer_free(mic_buffer);
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    rc = buffer_add_data(session->out_buffer, mic_token_buf.value, mic_token_buf.length);
    ssh_buffer_free(mic_buffer);
    if (rc < 0) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    return packet_send(session);
}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token_client){
    ssh_string token;
    char *hexa;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token, output_token = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    int deleg = 0;
    (void)user;
    (void)type;

    SSH_LOG(SSH_LOG_PACKET,"Received SSH_MSG_USERAUTH_GSSAPI_TOKEN");
    if (!session->gssapi || session->auth_state != SSH_AUTH_STATE_GSSAPI_TOKEN){
        ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_USERAUTH_GSSAPI_TOKEN in invalid state");
        return SSH_PACKET_USED;
    }
    token = buffer_get_ssh_string(packet);

    if (token == NULL){
        ssh_set_error(session, SSH_REQUEST_DENIED, "ssh_packet_userauth_gssapi_token: invalid packet");
        return SSH_PACKET_USED;
    }
    hexa = ssh_get_hexa(ssh_string_data(token),ssh_string_len(token));
    SSH_LOG(SSH_LOG_PACKET, "GSSAPI Token : %s",hexa);
    SAFE_FREE(hexa);
    input_token.length = ssh_string_len(token);
    input_token.value = ssh_string_data(token);
    if (session->gssapi->client.client_deleg_creds != GSS_C_NO_CREDENTIAL)
        creds = session->gssapi->client.client_deleg_creds;
    else
        creds = session->gssapi->client_creds;
    maj_stat = gss_init_sec_context(&min_stat,
            creds, &session->gssapi->ctx, session->gssapi->client.server_name, session->gssapi->client.oid,
            GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | (deleg ? GSS_C_DELEG_FLAG : 0),
            0, NULL, &input_token, NULL, &output_token, NULL, NULL);

    ssh_gssapi_log_error(0, "accepting token", maj_stat);
    ssh_string_free(token);
    if (GSS_ERROR(maj_stat)){
        ssh_gssapi_log_error(SSH_LOG_PROTOCOL, "Gssapi error", maj_stat);
        ssh_gssapi_free(session);
        session->gssapi=NULL;
        return SSH_PACKET_USED;
    }

    if (output_token.length != 0){
        hexa = ssh_get_hexa(output_token.value, output_token.length);
        SSH_LOG(SSH_LOG_PACKET, "GSSAPI: sending token %s",hexa);
        SAFE_FREE(hexa);
        token = ssh_string_new(output_token.length);
        ssh_string_fill(token, output_token.value, output_token.length);
        buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
        buffer_add_ssh_string(session->out_buffer,token);
        packet_send(session);
        ssh_string_free(token);
    }
    if(maj_stat == GSS_S_COMPLETE){
        session->auth_state = SSH_AUTH_STATE_NONE;
        ssh_gssapi_send_mic(session);
    }
    return SSH_PACKET_USED;
}
