/* Loopback ESL client for the isolated integration executable. */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define AMQP_API_REPLY_TEST_PORT 28741
#define AMQP_API_REPLY_TEST_PASSWORD "amqp-api-reply-test"

static int api_reply_read_packet(int fd, char *reply, size_t capacity)
{
	char header[1024] = { 0 };
	size_t used = 0, length = 0;
	char *content_length;
	while (used < sizeof(header) - 1) {
		if (recv(fd, header + used, 1, 0) != 1) return -1;
		used++;
		if (used >= 2 && header[used - 1] == '\n' && header[used - 2] == '\n') break;
	}
	if (used == sizeof(header) - 1) return -1;
	content_length = strstr(header, "Content-Length: ");
	if (content_length) length = (size_t)strtoul(content_length + strlen("Content-Length: "), NULL, 10);
	if (length >= capacity) return -1;
	if (!length) {
		if (used >= capacity) return -1;
		memcpy(reply, header, used + 1);
		return 0;
	}
	used = 0;
	while (used < length) {
		ssize_t n = recv(fd, reply + used, length - used, 0);
		if (n <= 0) return -1;
		used += (size_t)n;
	}
	reply[length] = '\0';
	return 0;
}

static int api_reply_send(int fd, const char *command)
{
	size_t left = strlen(command);
	while (left) {
		ssize_t n = send(fd, command, left, 0);
		if (n <= 0) return -1;
		command += n;
		left -= (size_t)n;
	}
	return 0;
}

static int api_reply_request(char *reply, size_t capacity)
{
	struct sockaddr_in address;
	char greeting[1024], auth[1024];
	int fd = -1, i, status = -1;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(AMQP_API_REPLY_TEST_PORT);
	for (i = 0; i < 100; i++) {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) return -1;
		if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) break;
		close(fd);
		fd = -1;
		switch_sleep(10000);
	}
	if (fd < 0) return -1;
	{
		struct timeval timeout = { 3, 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	}
	if (api_reply_read_packet(fd, greeting, sizeof(greeting)) != 0 ||
		!strstr(greeting, "Content-Type: auth/request")) goto done;
	if (api_reply_send(fd, "auth " AMQP_API_REPLY_TEST_PASSWORD "\n\n") != 0 ||
		api_reply_read_packet(fd, auth, sizeof(auth)) != 0 ||
		!strstr(auth, "Reply-Text: +OK")) goto done;
	if (api_reply_send(fd, "api amqp\n\n") != 0 ||
		api_reply_read_packet(fd, reply, capacity) != 0) goto done;
	status = 0;
done:
	close(fd);
	return status;
}
