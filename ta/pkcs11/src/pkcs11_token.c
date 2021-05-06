// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <config.h>
#include <confine_array_index.h>
#include <pkcs11_ta.h>
#include <printk.h>
#include <pta_system.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "attributes.h"
#include "handle.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"
#include "token_capabilities.h"

#ifdef PKCS11_SLOT_DESCRIPTION
#undef PKCS11_SLOT_DESCRIPTION
#define PKCS11_SLOT_DESCRIPTION		"Aurora PKCS11 TA"
#endif

#ifdef PKCS11_SLOT_MANUFACTURER
#undef PKCS11_SLOT_MANUFACTURER
#define PKCS11_SLOT_MANUFACTURER	"Open Mobile Platform"
#endif

#ifdef PKCS11_TOKEN_LABEL
#undef PKCS11_TOKEN_LABEL
#define PKCS11_TOKEN_LABEL		"Aurora PKCS#11 TA token"
#endif

#ifdef PKCS11_TOKEN_MANUFACTURER
#undef PKCS11_TOKEN_MANUFACTURER
#define PKCS11_TOKEN_MANUFACTURER	PKCS11_SLOT_MANUFACTURER
#endif

#ifdef PKCS11_TOKEN_MODEL
#undef PKCS11_TOKEN_MODEL
#define PKCS11_TOKEN_MODEL		"Aurora TA"
#endif

/* RNG chunk size used to split RNG generation to smaller sizes */
#define RNG_CHUNK_SIZE		512U

/*
 * Structure tracking client applications
 *
 * @link - chained list of registered client applications
 * @sessions - list of the PKCS11 sessions opened by the client application
 * @token_list - tokens related to this particular client application
 * @token_cnt - count of tokens which belong this CA
 * @object_handle_db - Database for object handles in name space of client
 */
struct pkcs11_client {
	TAILQ_ENTRY(pkcs11_client) link;
	struct session_list session_list;
	struct client_token_list token_list;
	uint32_t token_cnt;
	struct handle_db session_handle_db;
	struct handle_db object_handle_db;
};

struct client_token_temp {
	TAILQ_ENTRY(client_token_temp) link;
	struct ck_token *token;
};
TAILQ_HEAD(client_token_temp_list, client_token_temp);

struct client_init_in_progess {
	TAILQ_ENTRY(client_init_in_progess) link;
	struct client_token_temp_list client_token_temp_list;
	char client_salt[CLIENT_SALT_SIZE];
};
TAILQ_HEAD(client_init_in_progess_list, client_init_in_progess);

static struct client_list pkcs11_client_list =
	TAILQ_HEAD_INITIALIZER(pkcs11_client_list);

/* common list of currently loaded tokens */
static struct token_list pkcs11_token_list = 
	TAILQ_HEAD_INITIALIZER(pkcs11_token_list);

static struct client_init_in_progess_list all_ca_init_in_progess_list =
	TAILQ_HEAD_INITIALIZER(all_ca_init_in_progess_list);

static void close_ck_session(struct pkcs11_session *session);
static struct ck_token *get_token(struct pkcs11_client *client, uint32_t slot);
static uint32_t get_token_id(struct pkcs11_client *client, struct ck_token *token);

struct handle_db *get_object_handle_db(struct pkcs11_session *session)
{
	return &session->client->object_handle_db;
}

struct session_list *get_session_list(struct pkcs11_session *session)
{
	return &session->client->session_list;
}

struct pkcs11_client *tee_session2client(void *tee_session)
{
	struct pkcs11_client *client = NULL;

	TAILQ_FOREACH(client, &pkcs11_client_list, link)
		if (client == tee_session)
			break;

	return client;
}

struct pkcs11_session *pkcs11_handle2session(uint32_t handle,
					     struct pkcs11_client *client)
{
	return handle_lookup(&client->session_handle_db, handle);
}

struct ck_token *create_token(TEE_Identity *token_db_id)
{
	struct ck_token *token = NULL;

	if (!token_db_id)
		return NULL;

	/* check that token doesn't already exist */
	TAILQ_FOREACH(token, &pkcs11_token_list, link) {
		if (!TEE_MemCompare(&token_db_id->uuid,
				    &token->token_db_id.uuid,
				    sizeof(TEE_UUID))) {
			++token->ref_count;
			goto token_found;
		}
	}

	token = TEE_Malloc(sizeof(*token), TEE_MALLOC_FILL_ZERO);
	if (!token)
		return NULL;

	/* As per PKCS#11 spec, token resets to read/write state */
	token->state = PKCS11_TOKEN_READ_WRITE;
	token->session_count = 0;
	token->rw_session_count = 0;
	token->ref_count = 1;

	switch (token_db_id->login) {
	case TEE_LOGIN_USER:
		TEE_MemMove(token->sn, "USER", sizeof("USER"));
		break;
	case TEE_LOGIN_APPLICATION:
		TEE_MemMove(token->sn, "APP", sizeof("APP"));
		break;
	case TEE_LOGIN_APPLICATION_USER:
		TEE_MemMove(token->sn, "USERAPP", sizeof("USERAPP"));
		break;
	default:
		break;
	}

	TEE_MemMove(&token->token_db_id, token_db_id, sizeof(TEE_Identity));

	/* Insert a new token to common list of all tokens */
	TAILQ_INSERT_HEAD(&pkcs11_token_list, token, link);

token_found:
	return token;
}

void *reg_in_temp_ca_token_list(struct ck_token *token,
				char client_salt[CLIENT_SALT_SIZE])
{
	struct client_init_in_progess *ca_in_prog = NULL;
	struct client_token_temp *temp_token = NULL;

	if (!token || !client_salt)
		return NULL;

	TAILQ_FOREACH(ca_in_prog, &all_ca_init_in_progess_list, link) {
		if (!TEE_MemCompare(ca_in_prog->client_salt, client_salt,
				    CLIENT_SALT_SIZE)) {
			temp_token = TEE_Malloc(sizeof(*temp_token),
						TEE_MALLOC_FILL_ZERO);
			if (!temp_token)
				return NULL;

			temp_token->token = token;
			TAILQ_INSERT_HEAD(&ca_in_prog->client_token_temp_list,
					  temp_token, link);

			return ca_in_prog;
		}
	}

	/* New CA has started to init own tokens */
	ca_in_prog = TEE_Malloc(sizeof(*ca_in_prog), TEE_MALLOC_FILL_ZERO);
	if (!ca_in_prog)
		return NULL;

	/* New element in temp token list for particular CA */
	temp_token = TEE_Malloc(sizeof(*temp_token), TEE_MALLOC_FILL_ZERO);
	if (!temp_token) {
		TEE_Free(ca_in_prog);
		return NULL;
	}

	temp_token->token = token;

	TEE_MemMove(ca_in_prog->client_salt, client_salt, CLIENT_SALT_SIZE);
	TAILQ_INIT(&ca_in_prog->client_token_temp_list);
	TAILQ_INSERT_HEAD(&ca_in_prog->client_token_temp_list, temp_token,
			  link);
	TAILQ_INSERT_HEAD(&all_ca_init_in_progess_list, ca_in_prog, link);

	return ca_in_prog;
}

void remove_temp_ca_token_list(void *ca_token_temp_list)
{
	struct client_init_in_progess *ca_in_prog = NULL;
	struct client_token_temp *temp_token = NULL;

	if (!ca_token_temp_list)
		return;

	TAILQ_FOREACH(ca_in_prog, &all_ca_init_in_progess_list, link) {
		if (ca_in_prog == ca_token_temp_list) {
			while (!TAILQ_EMPTY(&ca_in_prog->
					   client_token_temp_list)) {
				temp_token = TAILQ_FIRST(
					&ca_in_prog->client_token_temp_list);
				TAILQ_REMOVE(&ca_in_prog->
					     client_token_temp_list,
					     temp_token,
					     link);
				TEE_Free(temp_token);
			}
			break;
		}
	}

	TAILQ_REMOVE(&all_ca_init_in_progess_list, ca_in_prog, link);
	TEE_Free(ca_in_prog);
}

void remove_token(struct ck_token *token)
{
	if (!token)
		return;

	if (token->ref_count > 1) {
		--token->ref_count;
	} else {
		TAILQ_REMOVE(&pkcs11_token_list, token, link);
		close_persistent_db(token);
		TEE_Free(token);
	}
}

struct pkcs11_client *register_client(void *ca_token_temp_list)
{
	struct pkcs11_client *client = NULL;
	struct client_token *client_token = NULL;
	struct client_token_temp *temp_token = NULL;
	struct client_init_in_progess *ca_in_prog = ca_token_temp_list;
	uint32_t client_token_cnt = 0;

	if (!ca_token_temp_list)
		return NULL;


	client = TEE_Malloc(sizeof(*client), TEE_MALLOC_FILL_ZERO);
	if (!client)
		return NULL;

	TAILQ_INSERT_HEAD(&pkcs11_client_list, client, link);
	TAILQ_INIT(&client->session_list);
	TAILQ_INIT(&client->token_list);
	handle_db_init(&client->session_handle_db);
	handle_db_init(&client->object_handle_db);

	/* Copy available for this client tokens and create slots */
	TAILQ_FOREACH(temp_token, &ca_in_prog->client_token_temp_list, link) {
		client_token = TEE_Malloc(sizeof(*client_token),
					  TEE_MALLOC_FILL_ZERO);
		if (!client_token) {
			TEE_Free(client);
			return NULL;
		}

		client_token->token = temp_token->token;
		client_token->slot = client_token_cnt;
		++client_token_cnt;

		/* load persistance database into RAM */
		if (!init_persistent_db(client_token->token)) {
			EMSG("Init database for token  %#"PRIx32" failed",
			     (int)client_token->token);
			TEE_Free(client_token);
			TEE_Free(client);
			return NULL;
		}

		TAILQ_INSERT_HEAD(&client->token_list, client_token, link);
	}

	client->token_cnt = client_token_cnt;
	return client;
}

void unregister_client(struct pkcs11_client *client)
{
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *next = NULL;
	struct client_token *client_token = NULL;

	if (!client) {
		EMSG("Invalid TEE session handle");
		return;
	}

	TAILQ_FOREACH_SAFE(session, &client->session_list, link, next)
		close_ck_session(session);

	/* Delete all token and RAM database for this client */
	TAILQ_FOREACH(client_token, &client->token_list, link)
		remove_token(client_token->token);
		

	TAILQ_REMOVE(&pkcs11_client_list, client, link);
	handle_db_destroy(&client->object_handle_db);
	handle_db_destroy(&client->session_handle_db);
	TEE_Free(client);
}

TEE_Result pkcs11_init(void)
{
	return TEE_SUCCESS;
}

void pkcs11_deinit(void)
{

}

/*
 * Currently no support for dual operations.
 */
enum pkcs11_rc set_processing_state(struct pkcs11_session *session,
				    enum processing_func function,
				    struct pkcs11_object *obj1,
				    struct pkcs11_object *obj2)
{
	enum pkcs11_proc_state state = PKCS11_SESSION_READY;
	struct active_processing *proc = NULL;

	if (session->processing)
		return PKCS11_CKR_OPERATION_ACTIVE;

	switch (function) {
	case PKCS11_FUNCTION_ENCRYPT:
		state = PKCS11_SESSION_ENCRYPTING;
		break;
	case PKCS11_FUNCTION_DECRYPT:
		state = PKCS11_SESSION_DECRYPTING;
		break;
	case PKCS11_FUNCTION_SIGN:
		state = PKCS11_SESSION_SIGNING;
		break;
	case PKCS11_FUNCTION_VERIFY:
		state = PKCS11_SESSION_VERIFYING;
		break;
	case PKCS11_FUNCTION_DIGEST:
		state = PKCS11_SESSION_DIGESTING;
		break;
	case PKCS11_FUNCTION_DERIVE:
		state = PKCS11_SESSION_READY;
		break;
	default:
		TEE_Panic(function);
		return -1;
	}

	proc = TEE_Malloc(sizeof(*proc), TEE_MALLOC_FILL_ZERO);
	if (!proc)
		return PKCS11_CKR_DEVICE_MEMORY;

	/* Boolean are default to false and pointers to NULL */
	proc->state = state;
	proc->tee_op_handle = TEE_HANDLE_NULL;

	if (obj1 && get_bool(obj1->attributes, PKCS11_CKA_ALWAYS_AUTHENTICATE))
		proc->always_authen = true;

	if (obj2 && get_bool(obj2->attributes, PKCS11_CKA_ALWAYS_AUTHENTICATE))
		proc->always_authen = true;

	session->processing = proc;

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_ck_slot_list(struct pkcs11_client *client,
				  uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	struct client_token *token = NULL;
	TEE_Param *out = params + 2;
	size_t out_size = 0;
	uint8_t *id = NULL;

	if (!client || ptypes != exp_pt ||
	    params[0].memref.size != TEE_PARAM0_SIZE_MIN)
		return PKCS11_CKR_ARGUMENTS_BAD;

	out_size = sizeof(token->slot) * client->token_cnt;

	if (out->memref.size < out_size) {
		out->memref.size = out_size;

		if (out->memref.buffer)
			return PKCS11_CKR_BUFFER_TOO_SMALL;
		else
			return PKCS11_CKR_OK;
	}

	id = out->memref.buffer;
	TAILQ_FOREACH(token, &client->token_list, link) {
		TEE_MemMove(id, &token->slot, sizeof(token->slot));
		id += sizeof(token->slot);
	}

	out->memref.size = out_size;

	return PKCS11_CKR_OK;
}

static void pad_str(uint8_t *str, size_t size)
{
	int n = strnlen((char *)str, size);

	TEE_MemFill(str + n, ' ', size - n);
}

static void set_token_description(struct pkcs11_slot_info *info)
{
	char desc[sizeof(info->slot_description) + 1] = { 0 };
	TEE_UUID dev_id = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	int n = 0;

	res = TEE_GetPropertyAsUUID(TEE_PROPSET_TEE_IMPLEMENTATION,
				    "gpd.tee.deviceID", &dev_id);
	if (res == TEE_SUCCESS) {
		n = snprintk(desc, sizeof(desc), PKCS11_SLOT_DESCRIPTION
			     " - TEE UUID %pUl", (void *)&dev_id);
	} else {
		n = snprintf(desc, sizeof(desc), PKCS11_SLOT_DESCRIPTION
			     " - No TEE UUID");
	}
	if (n < 0 || n >= (int)sizeof(desc))
		TEE_Panic(0);

	TEE_MemMove(info->slot_description, desc, n);
	pad_str(info->slot_description, sizeof(info->slot_description));
}

static struct ck_token *get_token(struct pkcs11_client *client, uint32_t slot)
{
	struct client_token *client_token = NULL;

	if (!client || slot > client->token_cnt - 1)
		return NULL;

	TAILQ_FOREACH(client_token, &client->token_list, link) {
		if (client_token->slot == slot)
			break;
	}

	return client_token->token;
}

static uint32_t get_token_id(struct pkcs11_client *client, struct ck_token *token)
{
	struct client_token *client_token = NULL;

	TAILQ_FOREACH(client_token, &client->token_list, link) {
		if (client_token->token == token)
			break;
	}

	return client_token->slot;
}

enum pkcs11_rc entry_ck_slot_info(struct pkcs11_client *client,
				  uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct pkcs11_slot_info info = {
		.slot_description = PKCS11_SLOT_DESCRIPTION,
		.manufacturer_id = PKCS11_SLOT_MANUFACTURER,
		.flags = PKCS11_CKFS_TOKEN_PRESENT,
		.hardware_version = PKCS11_SLOT_HW_VERSION,
		.firmware_version = PKCS11_SLOT_FW_VERSION,
	};

	COMPILE_TIME_ASSERT(sizeof(PKCS11_SLOT_DESCRIPTION) <=
			    sizeof(info.slot_description));
	COMPILE_TIME_ASSERT(sizeof(PKCS11_SLOT_MANUFACTURER) <=
			    sizeof(info.manufacturer_id));

	if (!client || ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!get_token(client, token_id))
		return PKCS11_CKR_SLOT_ID_INVALID;

	set_token_description(&info);

	pad_str(info.manufacturer_id, sizeof(info.manufacturer_id));

	out->memref.size = sizeof(info);
	TEE_MemMove(out->memref.buffer, &info, out->memref.size);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_ck_token_info(struct pkcs11_client *client,
				   uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_token_info info = {
		.manufacturer_id = PKCS11_TOKEN_MANUFACTURER,
		.model = PKCS11_TOKEN_MODEL,
		.max_session_count = UINT32_MAX,
		.max_rw_session_count = UINT32_MAX,
		.max_pin_len = PKCS11_TOKEN_PIN_SIZE_MAX,
		.min_pin_len = PKCS11_TOKEN_PIN_SIZE_MIN,
		.total_public_memory = UINT32_MAX,
		.free_public_memory = UINT32_MAX,
		.total_private_memory = UINT32_MAX,
		.free_private_memory = UINT32_MAX,
		.hardware_version = PKCS11_TOKEN_HW_VERSION,
		.firmware_version = PKCS11_TOKEN_FW_VERSION,
	};

	if (!client || ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(client, token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	pad_str(info.manufacturer_id, sizeof(info.manufacturer_id));
	pad_str(info.model, sizeof(info.model));

	TEE_MemMove(info.serial_number, token->sn, sizeof(info.serial_number));
	TEE_MemMove(info.label, token->db_main->label, sizeof(info.label));

	info.flags = token->db_main->flags;
	info.session_count = token->session_count;
	info.rw_session_count = token->rw_session_count;

	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return PKCS11_CKR_OK;
}

static void dmsg_print_supported_mechanism(unsigned int token_id __maybe_unused,
					   uint32_t *array __maybe_unused,
					   size_t count __maybe_unused)
{
	size_t __maybe_unused n = 0;

	if (TRACE_LEVEL < TRACE_DEBUG)
		return;

	for (n = 0; n < count; n++)
		DMSG("PKCS11 token %"PRIu32": mechanism 0x%04"PRIx32": %s",
		     token_id, array[n], id2str_mechanism(array[n]));
}

enum pkcs11_rc entry_ck_token_mecha_ids(struct pkcs11_client *client,
					uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token __maybe_unused *token = NULL;
	size_t count = 0;
	uint32_t *array = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(client, token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	count = out->memref.size / sizeof(*array);
	array = tee_malloc_mechanism_list(&count);

	if (out->memref.size < count * sizeof(*array)) {
		assert(!array);
		out->memref.size = count * sizeof(*array);
		if (out->memref.buffer)
			return PKCS11_CKR_BUFFER_TOO_SMALL;
		else
			return PKCS11_CKR_OK;
	}

	if (!array)
		return PKCS11_CKR_DEVICE_MEMORY;

	dmsg_print_supported_mechanism(token_id, array, count);

	out->memref.size = count * sizeof(*array);
	TEE_MemMove(out->memref.buffer, array, out->memref.size);

	TEE_Free(array);

	return rc;
}

enum pkcs11_rc entry_ck_token_mecha_info(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	uint32_t type = 0;
	struct ck_token *token = NULL;
	struct pkcs11_mechanism_info info = { };

	if (!client || ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &type, sizeof(uint32_t));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(client, token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	if (!mechanism_is_valid(type))
		return PKCS11_CKR_MECHANISM_INVALID;

	info.flags = mechanism_supported_flags(type);

	pkcs11_mechanism_supported_key_sizes(type, &info.min_key_size,
					     &info.max_key_size);

	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	DMSG("PKCS11 token %"PRIu32": mechanism 0x%"PRIx32" info",
	     token_id, type);

	return PKCS11_CKR_OK;
}

/* Select the ReadOnly or ReadWrite state for session login state */
static void set_session_state(struct pkcs11_client *client,
			      struct pkcs11_session *session, bool readonly)
{
	struct pkcs11_session *sess = NULL;
	enum pkcs11_session_state state = PKCS11_CKS_RO_PUBLIC_SESSION;

	/* Default to public session if no session already registered */
	if (readonly)
		state = PKCS11_CKS_RO_PUBLIC_SESSION;
	else
		state = PKCS11_CKS_RW_PUBLIC_SESSION;

	/*
	 * No need to check all client sessions, the first found in
	 * target token gives client login configuration.
	 */
	TAILQ_FOREACH(sess, &client->session_list, link) {
		assert(sess != session);

		if (sess->token == session->token) {
			switch (sess->state) {
			case PKCS11_CKS_RW_PUBLIC_SESSION:
			case PKCS11_CKS_RO_PUBLIC_SESSION:
				if (readonly)
					state = PKCS11_CKS_RO_PUBLIC_SESSION;
				else
					state = PKCS11_CKS_RW_PUBLIC_SESSION;
				break;
			case PKCS11_CKS_RO_USER_FUNCTIONS:
			case PKCS11_CKS_RW_USER_FUNCTIONS:
				if (readonly)
					state = PKCS11_CKS_RO_USER_FUNCTIONS;
				else
					state = PKCS11_CKS_RW_USER_FUNCTIONS;
				break;
			case PKCS11_CKS_RW_SO_FUNCTIONS:
				if (readonly)
					TEE_Panic(0);
				else
					state = PKCS11_CKS_RW_SO_FUNCTIONS;
				break;
			default:
				TEE_Panic(0);
			}
			break;
		}
	}

	session->state = state;
}

enum pkcs11_rc entry_ck_open_session(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	uint32_t flags = 0;
	struct ck_token *token = NULL;
	struct pkcs11_session *session = NULL;
	bool readonly = false;

	if (!client || ptypes != exp_pt ||
	    out->memref.size != sizeof(session->handle))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get(&ctrlargs, &token_id, sizeof(token_id));
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &flags, sizeof(flags));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(client, token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	/* Sanitize session flags */
	if (!(flags & PKCS11_CKFSS_SERIAL_SESSION))
		return PKCS11_CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (flags & ~(PKCS11_CKFSS_RW_SESSION | PKCS11_CKFSS_SERIAL_SESSION))
		return PKCS11_CKR_ARGUMENTS_BAD;

	readonly = !(flags & PKCS11_CKFSS_RW_SESSION);

	if (!readonly && token->state == PKCS11_TOKEN_READ_ONLY)
		return PKCS11_CKR_TOKEN_WRITE_PROTECTED;

	if (readonly) {
		/* Specifically reject read-only session under SO login */
		TAILQ_FOREACH(session, &client->session_list, link)
			if (pkcs11_session_is_so(session))
				return PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS;
	}

	session = TEE_Malloc(sizeof(*session), TEE_MALLOC_FILL_ZERO);
	if (!session)
		return PKCS11_CKR_DEVICE_MEMORY;

	session->handle = handle_get(&client->session_handle_db, session);
	if (!session->handle) {
		TEE_Free(session);
		return PKCS11_CKR_DEVICE_MEMORY;
	}

	session->token = token;
	session->client = client;

	LIST_INIT(&session->object_list);

	set_session_state(client, session, readonly);

	TAILQ_INSERT_HEAD(&client->session_list, session, link);

	session->token->session_count++;
	if (!readonly)
		session->token->rw_session_count++;

	TEE_MemMove(out->memref.buffer, &session->handle,
		    sizeof(session->handle));

	DMSG("Open PKCS11 session %"PRIu32, session->handle);

	return PKCS11_CKR_OK;
}

static void close_ck_session(struct pkcs11_session *session)
{
	release_active_processing(session);
	release_session_find_obj_context(session);

	/* Release all session objects */
	while (!LIST_EMPTY(&session->object_list))
		destroy_object(session,
			       LIST_FIRST(&session->object_list), true);

	TAILQ_REMOVE(&session->client->session_list, session, link);
	handle_put(&session->client->session_handle_db, session->handle);

	session->token->session_count--;
	if (pkcs11_session_is_read_write(session))
		session->token->rw_session_count--;

	TEE_Free(session);

	DMSG("Close PKCS11 session %"PRIu32, session->handle);
}

enum pkcs11_rc entry_ck_close_session(struct pkcs11_client *client,
				      uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	close_ck_session(session);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_ck_close_all_sessions(struct pkcs11_client *client,
					   uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	uint32_t token_id = 0;
	struct ck_token *token = NULL;
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *next = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(client, token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	DMSG("Close all sessions for PKCS11 token %"PRIu32, token_id);

	TAILQ_FOREACH_SAFE(session, &client->session_list, link, next)
		if (session->token == token)
			close_ck_session(session);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_ck_session_info(struct pkcs11_client *client,
				     uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	struct pkcs11_session_info info = {
		.flags = PKCS11_CKFSS_SERIAL_SESSION,
	};

	if (!client || ptypes != exp_pt || out->memref.size != sizeof(info))
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	info.slot_id = get_token_id(client, session->token);
	info.state = session->state;
	if (pkcs11_session_is_read_write(session))
		info.flags |= PKCS11_CKFSS_RW_SESSION;

	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	DMSG("Get find on PKCS11 session %"PRIu32, session->handle);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_ck_token_initialize(struct pkcs11_client *client,
					 uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	char label[PKCS11_TOKEN_LABEL_SIZE] = { 0 };
	struct pkcs11_session *sess = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct ck_token *token = NULL;
	TEE_Param *ctrl = params;
	uint32_t token_id = 0;
	uint32_t pin_size = 0;
	void *pin = NULL;
	struct pkcs11_object *obj = NULL;

	if (ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get(&ctrlargs, &token_id, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &label, PKCS11_TOKEN_LABEL_SIZE);
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	token = get_token(client, token_id);
	if (!token)
		return PKCS11_CKR_SLOT_ID_INVALID;

	if (token->db_main->flags & PKCS11_CKFT_SO_PIN_LOCKED) {
		IMSG("Token %"PRIu32": SO PIN locked", token_id);
		return PKCS11_CKR_PIN_LOCKED;
	}

	/* Check there's no open session on this token */
	TAILQ_FOREACH(client, &pkcs11_client_list, link)
		TAILQ_FOREACH(sess, &client->session_list, link)
			if (sess->token == token)
				return PKCS11_CKR_SESSION_EXISTS;

#if defined(CFG_PKCS11_TA_AUTH_TEE_IDENTITY)
	/* Check TEE Identity based authentication if enabled */
	if (token->db_main->flags & PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH) {
		rc = verify_identity_auth(token, PKCS11_CKU_SO);
		if (rc)
			return rc;
	}

	/* Detect TEE Identity based ACL usage activation with NULL PIN */
	if (!pin) {
		rc = setup_so_identity_auth_from_client(token);
		if (rc)
			return rc;

		goto inited;
	} else {
		/* De-activate TEE Identity based authentication */
		token->db_main->flags &=
			~PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH;
	}
#endif /* CFG_PKCS11_TA_AUTH_TEE_IDENTITY */

	if (!token->db_main->so_pin_salt) {
		/*
		 * The spec doesn't permit returning
		 * PKCS11_CKR_PIN_LEN_RANGE for this function, take another
		 * error code.
		 */
		if (pin_size < PKCS11_TOKEN_PIN_SIZE_MIN ||
		    pin_size > PKCS11_TOKEN_PIN_SIZE_MAX)
			return PKCS11_CKR_ARGUMENTS_BAD;

		rc = hash_pin(PKCS11_CKU_SO, pin, pin_size,
			      &token->db_main->so_pin_salt,
			      token->db_main->so_pin_hash);
		if (rc)
			return rc;

		goto inited;
	}

	rc = verify_pin(PKCS11_CKU_SO, pin, pin_size,
			token->db_main->so_pin_salt,
			token->db_main->so_pin_hash);
	if (rc) {
		unsigned int pin_count = 0;

		if (rc != PKCS11_CKR_PIN_INCORRECT)
			return rc;

		token->db_main->flags |= PKCS11_CKFT_SO_PIN_COUNT_LOW;
		token->db_main->so_pin_count++;

		pin_count = token->db_main->so_pin_count;
		if (pin_count == PKCS11_TOKEN_SO_PIN_COUNT_MAX - 1)
			token->db_main->flags |= PKCS11_CKFT_SO_PIN_FINAL_TRY;
		if (pin_count == PKCS11_TOKEN_SO_PIN_COUNT_MAX)
			token->db_main->flags |= PKCS11_CKFT_SO_PIN_LOCKED;

		update_persistent_db(token);

		return PKCS11_CKR_PIN_INCORRECT;
	}

inited:
	/* Make sure SO PIN counters are zeroed */
	token->db_main->flags &= ~(PKCS11_CKFT_SO_PIN_COUNT_LOW |
				   PKCS11_CKFT_SO_PIN_FINAL_TRY |
				   PKCS11_CKFT_SO_PIN_LOCKED |
				   PKCS11_CKFT_SO_PIN_TO_BE_CHANGED);
	token->db_main->so_pin_count = 0;

	TEE_MemMove(token->db_main->label, label, PKCS11_TOKEN_LABEL_SIZE);
	token->db_main->flags |= PKCS11_CKFT_TOKEN_INITIALIZED;
	/* Reset user PIN */
	token->db_main->user_pin_salt = 0;
	token->db_main->flags &= ~(PKCS11_CKFT_USER_PIN_INITIALIZED |
				   PKCS11_CKFT_USER_PIN_COUNT_LOW |
				   PKCS11_CKFT_USER_PIN_FINAL_TRY |
				   PKCS11_CKFT_USER_PIN_LOCKED |
				   PKCS11_CKFT_USER_PIN_TO_BE_CHANGED);

	update_persistent_db(token);

	/* Remove all persistent objects */
	while (!LIST_EMPTY(&token->object_list)) {
		obj = LIST_FIRST(&token->object_list);

		/* Try twice otherwise panic! */
		if (unregister_persistent_object(token, obj->uuid) &&
		    unregister_persistent_object(token, obj->uuid))
			TEE_Panic(0);

		cleanup_persistent_object(obj, token);
	}

	IMSG("PKCS11 token %"PRIu32": initialized", token_id);

	return PKCS11_CKR_OK;
}

static enum pkcs11_rc set_pin(struct pkcs11_session *session,
			      uint8_t *new_pin, size_t new_pin_size,
			      enum pkcs11_user_type user_type)
{
	struct ck_token *token = session->token;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint32_t flags_clear = 0;
	uint32_t flags_set = 0;

	if (token->db_main->flags & PKCS11_CKFT_WRITE_PROTECTED)
		return PKCS11_CKR_TOKEN_WRITE_PROTECTED;

	if (!pkcs11_session_is_read_write(session))
		return PKCS11_CKR_SESSION_READ_ONLY;

	if (IS_ENABLED(CFG_PKCS11_TA_AUTH_TEE_IDENTITY) &&
	    token->db_main->flags & PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH) {
		rc = setup_identity_auth_from_pin(token, user_type, new_pin,
						  new_pin_size);
		if (rc)
			return rc;

		goto update_db;
	}

	if (new_pin_size < PKCS11_TOKEN_PIN_SIZE_MIN ||
	    new_pin_size > PKCS11_TOKEN_PIN_SIZE_MAX)
		return PKCS11_CKR_PIN_LEN_RANGE;

	switch (user_type) {
	case PKCS11_CKU_SO:
		rc = hash_pin(user_type, new_pin, new_pin_size,
			      &token->db_main->so_pin_salt,
			      token->db_main->so_pin_hash);
		if (rc)
			return rc;
		token->db_main->so_pin_count = 0;
		flags_clear = PKCS11_CKFT_SO_PIN_COUNT_LOW |
			      PKCS11_CKFT_SO_PIN_FINAL_TRY |
			      PKCS11_CKFT_SO_PIN_LOCKED |
			      PKCS11_CKFT_SO_PIN_TO_BE_CHANGED;
		break;
	case PKCS11_CKU_USER:
		rc = hash_pin(user_type, new_pin, new_pin_size,
			      &token->db_main->user_pin_salt,
			      token->db_main->user_pin_hash);
		if (rc)
			return rc;
		token->db_main->user_pin_count = 0;
		flags_clear = PKCS11_CKFT_USER_PIN_COUNT_LOW |
			      PKCS11_CKFT_USER_PIN_FINAL_TRY |
			      PKCS11_CKFT_USER_PIN_LOCKED |
			      PKCS11_CKFT_USER_PIN_TO_BE_CHANGED;
		flags_set = PKCS11_CKFT_USER_PIN_INITIALIZED;
		break;
	default:
		return PKCS11_CKR_FUNCTION_FAILED;
	}

update_db:
	token->db_main->flags &= ~flags_clear;
	token->db_main->flags |= flags_set;

	update_persistent_db(token);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_ck_init_pin(struct pkcs11_client *client,
				 uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct pkcs11_session *session = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	TEE_Param *ctrl = params;
	uint32_t pin_size = 0;
	void *pin = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!pkcs11_session_is_so(session))
		return PKCS11_CKR_USER_NOT_LOGGED_IN;

	assert(session->token->db_main->flags & PKCS11_CKFT_TOKEN_INITIALIZED);

	IMSG("PKCS11 session %"PRIu32": init PIN", session->handle);

	return set_pin(session, pin, pin_size, PKCS11_CKU_USER);
}

static enum pkcs11_rc check_so_pin(struct pkcs11_session *session,
				   uint8_t *pin, size_t pin_size)
{
	struct ck_token *token = session->token;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(token->db_main->flags & PKCS11_CKFT_TOKEN_INITIALIZED);

	if (IS_ENABLED(CFG_PKCS11_TA_AUTH_TEE_IDENTITY) &&
	    token->db_main->flags & PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH)
		return verify_identity_auth(token, PKCS11_CKU_SO);

	if (token->db_main->flags & PKCS11_CKFT_SO_PIN_LOCKED)
		return PKCS11_CKR_PIN_LOCKED;

	rc = verify_pin(PKCS11_CKU_SO, pin, pin_size,
			token->db_main->so_pin_salt,
			token->db_main->so_pin_hash);
	if (rc) {
		unsigned int pin_count = 0;

		if (rc != PKCS11_CKR_PIN_INCORRECT)
			return rc;

		token->db_main->flags |= PKCS11_CKFT_SO_PIN_COUNT_LOW;
		token->db_main->so_pin_count++;

		pin_count = token->db_main->so_pin_count;
		if (pin_count == PKCS11_TOKEN_SO_PIN_COUNT_MAX - 1)
			token->db_main->flags |= PKCS11_CKFT_SO_PIN_FINAL_TRY;
		if (pin_count == PKCS11_TOKEN_SO_PIN_COUNT_MAX)
			token->db_main->flags |= PKCS11_CKFT_SO_PIN_LOCKED;

		update_persistent_db(token);

		if (token->db_main->flags & PKCS11_CKFT_SO_PIN_LOCKED)
			return PKCS11_CKR_PIN_LOCKED;

		return PKCS11_CKR_PIN_INCORRECT;
	}

	if (token->db_main->so_pin_count) {
		token->db_main->so_pin_count = 0;

		update_persistent_db(token);
	}

	if (token->db_main->flags & (PKCS11_CKFT_SO_PIN_COUNT_LOW |
				     PKCS11_CKFT_SO_PIN_FINAL_TRY)) {
		token->db_main->flags &= ~(PKCS11_CKFT_SO_PIN_COUNT_LOW |
					   PKCS11_CKFT_SO_PIN_FINAL_TRY);

		update_persistent_db(token);
	}

	return PKCS11_CKR_OK;
}

static enum pkcs11_rc check_user_pin(struct pkcs11_session *session,
				     uint8_t *pin, size_t pin_size)
{
	struct ck_token *token = session->token;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	if (IS_ENABLED(CFG_PKCS11_TA_AUTH_TEE_IDENTITY) &&
	    token->db_main->flags & PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH)
		return verify_identity_auth(token, PKCS11_CKU_USER);

	if (!token->db_main->user_pin_salt)
		return PKCS11_CKR_USER_PIN_NOT_INITIALIZED;

	if (token->db_main->flags & PKCS11_CKFT_USER_PIN_LOCKED)
		return PKCS11_CKR_PIN_LOCKED;

	rc = verify_pin(PKCS11_CKU_USER, pin, pin_size,
			token->db_main->user_pin_salt,
			token->db_main->user_pin_hash);
	if (rc) {
		unsigned int pin_count = 0;

		if (rc != PKCS11_CKR_PIN_INCORRECT)
			return rc;

		token->db_main->flags |= PKCS11_CKFT_USER_PIN_COUNT_LOW;
		token->db_main->user_pin_count++;

		pin_count = token->db_main->user_pin_count;
		if (pin_count == PKCS11_TOKEN_USER_PIN_COUNT_MAX - 1)
			token->db_main->flags |= PKCS11_CKFT_USER_PIN_FINAL_TRY;
		if (pin_count == PKCS11_TOKEN_USER_PIN_COUNT_MAX)
			token->db_main->flags |= PKCS11_CKFT_USER_PIN_LOCKED;

		update_persistent_db(token);

		if (token->db_main->flags & PKCS11_CKFT_USER_PIN_LOCKED)
			return PKCS11_CKR_PIN_LOCKED;

		return PKCS11_CKR_PIN_INCORRECT;
	}

	if (token->db_main->user_pin_count) {
		token->db_main->user_pin_count = 0;

		update_persistent_db(token);
	}

	if (token->db_main->flags & (PKCS11_CKFT_USER_PIN_COUNT_LOW |
				     PKCS11_CKFT_USER_PIN_FINAL_TRY)) {
		token->db_main->flags &= ~(PKCS11_CKFT_USER_PIN_COUNT_LOW |
					   PKCS11_CKFT_USER_PIN_FINAL_TRY);

		update_persistent_db(token);
	}

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_ck_set_pin(struct pkcs11_client *client,
				uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct pkcs11_session *session = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	uint32_t old_pin_size = 0;
	TEE_Param *ctrl = params;
	uint32_t pin_size = 0;
	void *old_pin = NULL;
	void *pin = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &old_pin_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&ctrlargs, &old_pin, old_pin_size);
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!pkcs11_session_is_read_write(session))
		return PKCS11_CKR_SESSION_READ_ONLY;

	if (pkcs11_session_is_so(session)) {
		if (!(session->token->db_main->flags &
		      PKCS11_CKFT_TOKEN_INITIALIZED))
			return PKCS11_CKR_GENERAL_ERROR;

		rc = check_so_pin(session, old_pin, old_pin_size);
		if (rc)
			return rc;

		IMSG("PKCS11 session %"PRIu32": set PIN", session->handle);

		return set_pin(session, pin, pin_size, PKCS11_CKU_SO);
	}

	if (!(session->token->db_main->flags &
	      PKCS11_CKFT_USER_PIN_INITIALIZED))
		return PKCS11_CKR_GENERAL_ERROR;

	rc = check_user_pin(session, old_pin, old_pin_size);
	if (rc)
		return rc;

	IMSG("PKCS11 session %"PRIu32": set PIN", session->handle);

	return set_pin(session, pin, pin_size, PKCS11_CKU_USER);
}

static void session_login_user(struct pkcs11_session *session)
{
	struct pkcs11_client *client = session->client;
	struct pkcs11_session *sess = NULL;

	TAILQ_FOREACH(sess, &client->session_list, link) {
		if (sess->token != session->token)
			continue;

		if (pkcs11_session_is_read_write(sess))
			sess->state = PKCS11_CKS_RW_USER_FUNCTIONS;
		else
			sess->state = PKCS11_CKS_RO_USER_FUNCTIONS;
	}
}

static void session_login_so(struct pkcs11_session *session)
{
	struct pkcs11_client *client = session->client;
	struct pkcs11_session *sess = NULL;

	TAILQ_FOREACH(sess, &client->session_list, link) {
		if (sess->token != session->token)
			continue;

		if (pkcs11_session_is_read_write(sess))
			sess->state = PKCS11_CKS_RW_SO_FUNCTIONS;
		else
			TEE_Panic(0);
	}
}

static void session_logout(struct pkcs11_session *session)
{
	struct pkcs11_client *client = session->client;
	struct pkcs11_session *sess = NULL;

	TAILQ_FOREACH(sess, &client->session_list, link) {
		struct pkcs11_object *obj = NULL;
		struct pkcs11_object *tobj = NULL;
		uint32_t handle = 0;

		if (sess->token != session->token)
			continue;

		release_active_processing(session);

		/* Destroy private session objects */
		LIST_FOREACH_SAFE(obj, &sess->object_list, link, tobj) {
			if (object_is_private(obj->attributes))
				destroy_object(sess, obj, true);
		}

		/*
		 * Remove handle of token private objects from
		 * sessions object_handle_db
		 */
		LIST_FOREACH(obj, &session->token->object_list, link) {
			handle = pkcs11_object2handle(obj, session);

			if (handle && object_is_private(obj->attributes))
				handle_put(get_object_handle_db(sess), handle);
		}

		release_session_find_obj_context(session);

		if (pkcs11_session_is_read_write(sess))
			sess->state = PKCS11_CKS_RW_PUBLIC_SESSION;
		else
			sess->state = PKCS11_CKS_RO_PUBLIC_SESSION;
	}
}

enum pkcs11_rc entry_ck_login(struct pkcs11_client *client,
			      uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct pkcs11_session *session = NULL;
	struct pkcs11_session *sess = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	TEE_Param *ctrl = params;
	uint32_t user_type = 0;
	uint32_t pin_size = 0;
	void *pin = NULL;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &user_type, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get(&ctrlargs, &pin_size, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = serialargs_get_ptr(&ctrlargs, &pin, pin_size);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	switch (user_type) {
	case PKCS11_CKU_SO:
		if (pkcs11_session_is_so(session))
			return PKCS11_CKR_USER_ALREADY_LOGGED_IN;

		if (pkcs11_session_is_user(session))
			return PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

		TAILQ_FOREACH(sess, &client->session_list, link)
			if (sess->token == session->token &&
			    !pkcs11_session_is_read_write(sess))
				return PKCS11_CKR_SESSION_READ_ONLY_EXISTS;

		/*
		 * This is the point where we could check if another client
		 * has another user or SO logged in.
		 *
		 * The spec says:
		 * CKR_USER_TOO_MANY_TYPES: An attempt was made to have
		 * more distinct users simultaneously logged into the token
		 * than the token and/or library permits. For example, if
		 * some application has an open SO session, and another
		 * application attempts to log the normal user into a
		 * session, the attempt may return this error. It is not
		 * required to, however. Only if the simultaneous distinct
		 * users cannot be supported does C_Login have to return
		 * this value. Note that this error code generalizes to
		 * true multi-user tokens.
		 *
		 * So it's permitted to have another user or SO logged in
		 * from another client.
		 */

		rc = check_so_pin(session, pin, pin_size);
		if (!rc)
			session_login_so(session);

		break;

	case PKCS11_CKU_USER:
		if (pkcs11_session_is_so(session))
			return PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

		if (pkcs11_session_is_user(session))
			return PKCS11_CKR_USER_ALREADY_LOGGED_IN;

		/*
		 * This is the point where we could check if another client
		 * has another user or SO logged in.
		 * See comment on CKR_USER_TOO_MANY_TYPES above.
		 */

		rc = check_user_pin(session, pin, pin_size);
		if (!rc)
			session_login_user(session);

		break;

	case PKCS11_CKU_CONTEXT_SPECIFIC:
		return PKCS11_CKR_OPERATION_NOT_INITIALIZED;

	default:
		return PKCS11_CKR_USER_TYPE_INVALID;
	}

	if (!rc)
		IMSG("PKCS11 session %"PRIu32": login", session->handle);

	return rc;
}

enum pkcs11_rc entry_ck_logout(struct pkcs11_client *client,
			       uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct pkcs11_session *session = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	TEE_Param *ctrl = params;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (pkcs11_session_is_public(session))
		return PKCS11_CKR_USER_NOT_LOGGED_IN;

	session_logout(session);

	IMSG("PKCS11 session %"PRIu32": logout", session->handle);

	return PKCS11_CKR_OK;
}

static TEE_Result seed_rng_pool(void *seed, size_t length)
{
	static const TEE_UUID system_uuid = PTA_SYSTEM_UUID;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t ret_orig = 0;

	params[0].memref.buffer = seed;
	params[0].memref.size = (uint32_t)length;

	res = TEE_OpenTASession(&system_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
				&sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("Can't open session to system PTA");
		return res;
	}

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_ADD_RNG_ENTROPY,
				  param_types, params, &ret_orig);
	if (res != TEE_SUCCESS)
		EMSG("Can't invoke system PTA");

	TEE_CloseTASession(sess);
	return res;
}

enum pkcs11_rc entry_ck_seed_random(struct pkcs11_client *client,
				    uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *in = params + 1;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	TEE_Result res = TEE_SUCCESS;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (in->memref.size && !in->memref.buffer)
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!in->memref.size)
		return PKCS11_CKR_OK;

	res = seed_rng_pool(in->memref.buffer, in->memref.size);
	if (res != TEE_SUCCESS)
		return PKCS11_CKR_FUNCTION_FAILED;

	DMSG("PKCS11 session %"PRIu32": seed random", session->handle);

	return PKCS11_CKR_OK;
}

enum pkcs11_rc entry_ck_generate_random(struct pkcs11_client *client,
					uint32_t ptypes, TEE_Param *params)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param *ctrl = params;
	TEE_Param *out = params + 2;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct serialargs ctrlargs = { };
	struct pkcs11_session *session = NULL;
	void *buffer = NULL;
	size_t buffer_size = 0;
	uint8_t *data = NULL;
	size_t left = 0;

	if (!client || ptypes != exp_pt)
		return PKCS11_CKR_ARGUMENTS_BAD;

	serialargs_init(&ctrlargs, ctrl->memref.buffer, ctrl->memref.size);

	rc = serialargs_get_session_from_handle(&ctrlargs, client, &session);
	if (rc)
		return rc;

	if (serialargs_remaining_bytes(&ctrlargs))
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (out->memref.size && !out->memref.buffer)
		return PKCS11_CKR_ARGUMENTS_BAD;

	if (!out->memref.size)
		return PKCS11_CKR_OK;

	buffer_size = MIN(out->memref.size, RNG_CHUNK_SIZE);
	buffer = TEE_Malloc(buffer_size, TEE_MALLOC_FILL_ZERO);
	if (!buffer)
		return PKCS11_CKR_DEVICE_MEMORY;

	data = out->memref.buffer;
	left = out->memref.size;

	while (left) {
		size_t count = MIN(left, buffer_size);

		TEE_GenerateRandom(buffer, count);
		TEE_MemMove(data, buffer, count);

		data += count;
		left -= count;
	}

	DMSG("PKCS11 session %"PRIu32": generate random", session->handle);

	TEE_Free(buffer);

	return PKCS11_CKR_OK;
}
