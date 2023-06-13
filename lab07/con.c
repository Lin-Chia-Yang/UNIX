#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // server address and port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(0x1337);

    // connect to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }

    // receive data from the server
    char buffer[1024];
    int num_bytes = recv(sockfd, buffer, sizeof(buffer), 0);
    if (num_bytes == -1) {
        perror("receive failed");
        exit(EXIT_FAILURE);
    }

    // print the received data
    printf("Received data: %.*s\n", num_bytes, buffer);

    // close the socket
    close(sockfd);

    return 0;
}