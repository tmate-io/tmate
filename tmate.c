#include "tmate.h"

struct tmate_encoder *tmate_encoder;

static struct tmate_ssh_client client;
static struct tmate_encoder encoder;
static struct tmate_decoder decoder;

void tmate_client_start(void)
{
	tmate_encoder_init(&encoder);
	tmate_decoder_init(&decoder);
	tmate_encoder = &encoder;

	tmate_ssh_client_init(&client, &encoder, &decoder);

	tmate_write_header();
}
