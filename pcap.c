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
/* 세션 열기 */
handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
if (handle == NULL) {
   fprintf(stderr, "장치를 열 업습니다.  %s: %s\n", dev, errbuf);
   return(2);
}
/* 필터 컴파일, 적용 */
if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
   fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
   return(2);
}
if (pcap_setfilter(handle, &fp) == -1) {
   fprintf(stderr, "필터를 설치할 수 없습니다.  %s: %s\n", filter_exp, pcap_geterr(handle));
   return(2);

   }


