#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <unistd.h>

#ifdef DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

typedef struct {
    uint16_t id;
    uint8_t flags[2];
    uint16_t qdcount, ancount, nscount, arcount;
} HEADER;

static struct {
    uint16_t family, port;
    uint32_t ip;
    uint8_t padding[8];
} addr = {
    .family = AF_INET,
    .port = __bswap_constant_16(53),
};

static const uint8_t ip[4] = {IP};

static int sock_init(void)
{
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0) {
        return sock;
    }

    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
        printf("bind() failed\n");
        close(sock);
        return -1;
    }

    return sock;
}

int main(void)
{
    int sock, len;
    socklen_t addrlen;
    uint8_t data[65536];
    HEADER *h;
    uint8_t *p, *op, *end, *name, atype;

    uint16_t i, n, type, size;

    sock = sock_init();
    if(sock < 0) {
        return 1;
    }

    do {
    CONTINUE:
        addrlen = sizeof(addr);
        len = recvfrom(sock, data, sizeof(data), 0, (struct sockaddr*)&addr, &addrlen);
        if(len < 0) {
            printf("recvfrom error\n");
            break;
        }

        if(len < sizeof(HEADER)) {
            debug("small packet\n");
            continue;
        }

        h = (void*)data;
        p = (void*)(h + 1);
        end = data + len;
        atype = 0;

        debug("request from: %u.%u.%u.%u:%u (%u, %u, %u %u %u %u)\n",
              addr.ip[0], addr.ip[1], addr.ip[2], addr.ip[3],
              htons(addr.port), len, htons(h->id),
              htons(h->qdcount), htons(h->ancount), htons(h->nscount), htons(h->arcount));

        if(h->flags[0] & (0x80 | 0x78)) {
            //only care about requests and QUERY
            debug("response or not QUERY (%u)\n", h->flags[0]);
            continue;
        }

        if(h->ancount) {
            //dont support answer entries
            debug("has answer entries\n");
            continue;
        }

        if(h->nscount) {
            //dont support authority entries
            debug("has authority entries\n");
            continue;
        }

        //qr (1), opcode (4), aa (1), tc (1), rd (1)
        //ra (1), unused (1), ad (1), cd (1), rcode (4)
        h->flags[0] = ((1 << 7) | (0 << 3) | (0 << 2) | (0 << 1) | (h->flags[0] & 1));
        h->flags[1] = (0);

        n = htons(h->qdcount);
        for(i = 0; i != n; i++) {
            if(p == end) {
                debug("malformed question\n");
                goto CONTINUE;
            }

            if(i == 0) {
                name = p;
            }

            while((len = *p++)) {
                if(p + len + 1 > end){
                    debug("malformed question\n");
                    goto CONTINUE;
                }
                p += len;
            }

            if(p + 4 > end) {
                debug("malformed question\n");
                goto CONTINUE;
            }

            type = (p[1] | (p[0] << 8)); p += 2;
            //class = (p[1] | (p[0] << 8));
            p += 2;
            debug("QTYPE: %u QCLASS: %u\n", type, 0);

            switch(type) {
                case 1: //A
                //case 15: //MX
                case 16: //TXT
                //case 28: //AAAA
                    break;

                default: {
                    debug("unknown QTYPE %u\n", type);
                    break;
                }
            }

            if(type == 0 || type >= 256) {
                debug("zero/large type\n");
                continue;
            }

            atype = type;
        }

        op = p;

        n = htons(h->arcount);
        for(i = 0; i != n; i++) {
            if(p == end) {
                debug("malformed resource\n");
                goto CONTINUE;
            }

            while((len = *p++)) {
                if(p + len + 1 > end){
                    debug("malformed resource\n");
                    goto CONTINUE;
                }
                p += len;
            }

            if(p + 10 > end) {
                debug("malformed resource\n");
                goto CONTINUE;
            }

            type = (p[1] | (p[0] << 8)); p += 2;
            //class = (p[1] | (p[0] << 8));
            p += 2;
            //ttl = (p[3] | (p[2] << 8) | (p[1] << 16) | (p[0] << 24));
            p += 4;
            size = (p[1] | (p[0] << 8)); p += 2;

            if(p + size > end) {
                debug("malformed resource\n");
                goto CONTINUE;
            }

            debug("TYPE: %u CLASS: %u TTL: %u size: %u\n", type, 0, 0, size);

            switch(type) {
                case 41: {
                    /* OPT */
                    break;
                }

                default: {
                    debug("unknown RR TYPE %u\n", type);
                    break;
                }
            }

            p += size;
        }

        if(p == end) {
            h->arcount = 0;
            if(atype == 1 || atype == 16) {
                h->ancount = __bswap_constant_16(1);

                *op++ = 0xC0; *op++ = 12; //name at +12
                *op++ = 0; *op++ = atype; //type
                *op++ = 0; *op++ = 1; //class: IN

                /* ttl: 2048s for A record, 0 for TXT record*/
                *op++ = 0; *op++ = 0;
                *op++ = (atype == 1) ? 8 : 0;
                *op++ = 0;

                if(atype == 1) {
                    /* A */
                    //CHANGE RESPONSE BASED ON "NAME" here
                    *op++ = 0; *op++ = 4;
                    memcpy(op, ip, 4); op += 4;
                }
                else {
                    *op++ = 0; *op++ = 1; *op++ = 0;
                }
            }

            sendto(sock, data, op - data, 0, (struct sockaddr*)&addr, addrlen);
            debug("sent response!\n");
        } else {
            debug("malformed packet\n");
        }
    } while(1);

    return 0;
}
