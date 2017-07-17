int main(int argc, char *argv[])
{
pcap_t *handle;         /* Session handle */
char *dev;         /* The device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
struct bpf_program fp;      /* The compiled filter */
char filter_exp[] = "port 80";   /* The filter expression */
bpf_u_int32 mask;      /* Our netmask */
bpf_u_int32 net;      /* Our IP */
struct pcap_pkthdr header;   /* The header that pcap gives us */
const u_char *packet;      /* The actual packet */
int pcap_mod=0;            /*계속 진행해주기 위한 코드*/


/* Define the device */
dev = pcap_lookupdev(errbuf);
if (dev == NULL) {
   fprintf(stderr, "기본 장치를 찾지 못했습니다. : %s\n", errbuf);
   return(2);
}
/* Find the properties for the device */
if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
   fprintf(stderr, "장치로부터 netstat 값을 가져올 수 없습니다. %s: %s\n", dev, errbuf);
   net = 0;
   mask = 0;
}
