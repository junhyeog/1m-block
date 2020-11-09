#include <errno.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <linux/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

typedef struct {
  u_int32_t id;
  bool isDrop;
} IdIsDrop;

static const int MAX_HOST_SIZE = 100;
static const int MAX_DATA_SIZE = 100000;  // 65535
static const int MAX_HTTPMETHOD_SIZE = 10;

static char target_host[MAX_HOST_SIZE];
static char httpMethods[][MAX_HTTPMETHOD_SIZE] = {"GET ", "POST", "HEAD", "PUT ", "DELETE", "OPTIONS", "CONNECT", "TRACE", "PATCH"};

int F[MAX_DATA_SIZE];
std::unordered_set<std::string> unsafe_sites;

/**
* @ brief return vetor of idx
*/
std::vector<int> str_cmp(unsigned char *src, int src_len, unsigned char *dst, int dst_len) {
  // src string x
  unsigned char *x = (unsigned char *)malloc(sizeof(unsigned char) * (src_len + 1));
  memcpy(x, "?", sizeof(unsigned char));
  memcpy(x + 1, src, sizeof(unsigned char) * src_len);

  // dst string y
  unsigned char *y = (unsigned char *)malloc(sizeof(unsigned char) * (dst_len + 1));
  memcpy(y, "?", sizeof(unsigned char));
  memcpy(y + 1, dst, sizeof(unsigned char) * dst_len);

  // KMP init
  F[0] = -1;
  for (int i = 1; i < dst_len + 1; i++) {
    int pos = F[i - 1];
    while (pos != -1 && y[pos + 1] != y[i]) pos = F[pos];
    if (y[pos + 1] == y[i]) F[i] = pos + 1;
  }

  // KMP
  std::vector<int> ans;
  int pos = 0;
  for (int i = 1; i < src_len + 1; i++) {
    while (pos != -1 && y[pos + 1] != x[i]) pos = F[pos];
    pos = pos + 1;

    if (pos == dst_len) {
      ans.push_back(i - pos + 1);
      pos = F[pos];
    }
  }
  free(x);
  free(y);
  return ans;
}

static void init_unsafe_sites(char *file_name) {
  std::ifstream in(file_name);
  std::string s;
  while (in.is_open() && (in >> s)) unsafe_sites.insert(s);
  return;
}

static bool is_http(unsigned char *data) {
  // ipv4
  struct libnet_ipv4_hdr *iphdr = (struct libnet_ipv4_hdr *)data;
  if (iphdr->ip_v != 4 || iphdr->ip_p != IPPROTO_TCP) return 0;

  // tcp
  struct libnet_tcp_hdr *tcphdr =
      (struct libnet_tcp_hdr *)(data + (iphdr->ip_hl << 2));
  char *payload = (char *)(data + (iphdr->ip_hl << 2) + (tcphdr->th_off << 2));

  // http
  for (int i = 0; i < sizeof(httpMethods) / MAX_HTTPMETHOD_SIZE; i++) {
    if (!strncmp(httpMethods[i], payload, strlen(httpMethods[i])) ||
        !strncmp(httpMethods[i], payload + 1, strlen(httpMethods[i])) ||
        !strncmp(httpMethods[i], payload + 2, strlen(httpMethods[i]))) {
      printf("[+] Found HTTP packet\n");
      return 1;
    }
  }
  return 0;
}

static bool check_drop(unsigned char *data, int len) {
  // check host
  unsigned char target[MAX_HOST_SIZE + 8] = "Host: ";
  std::vector<int> indices = str_cmp(data, len, target, 6);
  if (!indices.size()) {
    printf("Can't find host\n");
    return 0;
  } else if (indices.size() != 1) {
    printf("Found more than one host\n");
    return 1;  //TODO what shoud I do
  }

  // get host
  int host_len = 0;
  int begin_idx = indices[0] - 1;
  for (int i = begin_idx + 6; i < len - 1; i++) {
    if (data[i] == '\r' && data[i + 1] == '\n') {
      host_len = i - begin_idx - 6;
      break;
    }
  }
  if (host_len == 0) {
    printf("Can't find host\n");
    return 0;
  }
  std::string host;
  for (int i = 0; i < host_len; i++) host.push_back((char)(data[begin_idx + 6 + i]));
  printf("[+] Host: %s\n", host.c_str());

  // cmp with unsafe_sites
  auto it = unsafe_sites.find(host);
  if (it == unsafe_sites.end()) return 0;
  return 1;
}

/* returns packet id */
static IdIsDrop print_pkt(struct nfq_data *tb) {  //! check Host
  bool isDrop = 0;
  u_int32_t id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  struct nfqnl_msg_packet_hw *hwph;
  u_int32_t mark, ifi;
  int ret;
  unsigned char *data;

  ph = nfq_get_msg_packet_hdr(tb);
  if (ph) {
    id = ntohl(ph->packet_id);
    // printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
  }

  hwph = nfq_get_packet_hw(tb);
  if (hwph) {
    int i, hlen = ntohs(hwph->hw_addrlen);

    // printf("hw_src_addr=");
    // for (i = 0; i < hlen - 1; i++) printf("%02x:", hwph->hw_addr[i]);
    // printf("%02x ", hwph->hw_addr[hlen - 1]);
  }

  mark = nfq_get_nfmark(tb);
  // if (mark) printf("mark=%u ", mark);

  ifi = nfq_get_indev(tb);
  // if (ifi) printf("indev=%u ", ifi);

  ifi = nfq_get_outdev(tb);
  // if (ifi) printf("outdev=%u ", ifi);
  ifi = nfq_get_physindev(tb);
  // if (ifi) printf("physindev=%u ", ifi);

  ifi = nfq_get_physoutdev(tb);
  // if (ifi) printf("physoutdev=%u ", ifi);

  ret = nfq_get_payload(tb, &data);
  if (ret >= 0) {
    // printf("payload_len=%d ", ret);
    if (is_http(data) && check_drop(data, ret)) isDrop = 1, printf("[+] Dropped packet");
  }
  fputc('\n', stdout);

  return {id, isDrop};
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
  IdIsDrop info = print_pkt(nfa);
  printf("entering callback\n");
  return nfq_set_verdict(qh, info.id, info.isDrop ? NF_DROP : NF_ACCEPT, 0, NULL);
}

void usage() {
  printf("syntax : 1m-block <site list file>\n");
  printf("sample : 1m-block top-1m.txt\n");
  return;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    usage();
    return -1;
  }

  init_unsafe_sites(argv[1]);
  if (unsafe_sites.empty()) {
    printf("Can't find unsafe sites\n");
    return -1;
  }

  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096] __attribute__((aligned));

  printf("opening library handle\n");
  h = nfq_open();
  if (!h) {
    fprintf(stderr, "error during nfq_open()\n");
    exit(1);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    exit(1);
  }

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    exit(1);
  }

  printf("binding this socket to queue '0'\n");
  qh = nfq_create_queue(h, 0, &cb, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  fd = nfq_fd(h);

  for (;;) {
    if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
      printf("pkt received\n");
      nfq_handle_packet(h, buf, rv);
      continue;
    }
    /* if your application is too slow to digest the packets that
     * are sent from kernel-space, the socket buffer that we use
     * to enqueue packets may fill up returning ENOBUFS. Depending
     * on your application, this error may be ignored.
     * nfq_nlmsg_verdict_putPlease, see the doxygen documentation of this
     * library on how to improve this situation.
     */
    if (rv < 0 && errno == ENOBUFS) {
      printf("losing packets!\n");
      continue;
    }
    perror("recv failed");
    break;
  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

#ifdef INSANE
  /* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! */
  printf("unbinding from AF_INET\n");
  nfq_unbind_pf(h, AF_INET);
#endif

  printf("closing library handle\n");
  nfq_close(h);

  exit(0);
}
