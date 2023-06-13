# Compito finale - Programmazione P4

## Introduzione

![topology](./topo.png)

L'obiettivo del progetto consiste nel realizzare un programma P4 per switch in grado di unire le peculiarità di due esercitazioni viste a lezione:

- Inoltro pacchetti con header custom (Tunneling)
- Flusso asimmetrico

Come detto, il programma deve fornire la possibilità di monitorare il traffico tra flussi e la relativa asimmetria (in termini di quantità dati inviata) nel regolare traffico IPV4, quindi senza header custom. In aggiunta, va processato il traffico con header modificato, in modo tale da contenere 3 campi di interesse, oltre a quelli necessari per il funzionamento del tunneling, ovvero:

- Un campo PID che contenga l'identificativo del processo che ha inviato il messaggio
- Un campo dst_id che contenga la porta dello switch da cui inviare il messaggio
- Un campo IP_Mal che contenga l'indirizzo IP destinazione (di default inizializzato a 0.0.0.0)
- Un campo TIME che contenga un valore Unix Time (defalut a 0)
- un campo flag che possa contenere un intero (inizializzato a 0)

## Implementazione

Si parte dalla base dell'esercitazione Asymmetric Flow, quindi con la possibilità di monitorare il flusso asimmetrico di dati inviati tra due host.
Una volta che la THRESHOLD viene superata, invece di eseguire una drop di tutti i pacchetti ricevuti a seguire, semplicemente salveremo in un registro l'ultimo pacchetto che ha causato il superamento della threshold continuando a inoltrare, come da normale procedura, tutti i pacchetti che verranno ricevuto a seguire.
In particolare, andremo a salvare in un registro i seguenti dati, riferiti al pacchetto che ha ecceduto la threshold:

- Ip sorgente
- Ip destinazione
- Timestamp

Il registro, chiamato THRESHOLDI, sarà quindi composto da 3 campi, due  di 32 bit e uno da 48, per un totale di 112 bit.

### Parser

```c
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.myTunnel);
        transition select(hdr.myTunnel.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}
```

Il parser è stato modificato per poter processare i pacchetti con header custom, in particolare, è stato aggiunto un nuovo stato per il parsing dell'header myTunnel, che contiene i campi aggiuntivi necessari per il tunneling.

### Igress

#### IPv4

Per quanto riguarda il traffico IPv4, il programma deve essere in grado di processare i pacchetti in arrivo, contare il numero di pacchetti nei flussi in modo tale da poter calcolare la soglia di traffico, e inoltrare i pacchetti in arrivo.

```c
action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    standard_metadata.egress_spec = port;
    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = dstAddr;
    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
}

table ipv4_lpm {
    key = {
        hdr.ipv4.dstAddr: lpm;
    }
    counters = c;
    actions = {
        ipv4_forward;
        drop;
        NoAction;
    }
    size = 1024;
    default_action = NoAction();
}

```

Di default, il programma inoltra i pacchetti ricevuti, modificando opportunamente i campi dell'header ethernet e decrementando il TTL dell'header IPv4.

```c

register<bit<48>>(1024) last_seen;
register<bit<64>>(1024) flows;
register<bit<112>>(1) TRESHOLDI;

action save_last_seen(bit<112> pkt_data) {
      TRESHOLDI.write(0, pkt_data);
}

action get_inter_packet_gap(out bit<48> interval,bit<32> flow_id)
{
  bit<48> last_pkt_cnt;
  bit<32> index;
  /* Get the time the previous packet was seen */
  last_seen.read(last_pkt_cnt,flow_id);
  interval = last_pkt_cnt + 1;
  /* Update the register with the new timestamp */
  last_seen.write((bit<32>)flow_id,
  interval);
}

action compute_flow_id () {
  meta.ingress_metadata.my_flowID[31:0]=hdr.ipv4.srcAddr;
  meta.ingress_metadata.my_flowID[63:32]=hdr.ipv4.dstAddr;
}

action compute_reg_index () {
  // Each flow ID is hashed into d=3 different locations
    hash(meta.ingress_metadata.hashed_flow, HashAlgorithm.crc16, HASH_BASE,
        {hdr.ipv4.srcAddr, 7w11, hdr.ipv4.dstAddr}, HASH_MAX);
    hash(meta.ingress_metadata.hashed_flow_opposite, HashAlgorithm.crc16, HASH_BASE,
        {hdr.ipv4.dstAddr, 7w11, hdr.ipv4.srcAddr}, HASH_MAX);
}

apply{
  if (hdr.ipv4.isValid() && !hdr.myTunnel.isValid()) {
      ipv4_lpm.apply();
      bit<48> tmp;
      bit<32> flow;
      bit<32> flow_opp;
      compute_reg_index();
      bit<48> last_pkt_cnt;
      bit<48> last_pkt_cnt_opp;
      /* Get the time the previous packet was seen */
      flow = meta.ingress_metadata.hashed_flow;
      flow_opp = meta.ingress_metadata.hashed_flow_opposite;
      last_seen.read(last_pkt_cnt,flow);
      last_seen.read(last_pkt_cnt_opp,flow_opp);
      tmp = last_pkt_cnt - last_pkt_cnt_opp + 1;
      get_inter_packet_gap(last_pkt_cnt,flow);
      if(tmp == TRESHOLD) {
          bit<112> pkt_data = 0x0;
          pkt_data[31:0] = hdr.ipv4.srcAddr;
          pkt_data[63:32] = hdr.ipv4.dstAddr;
          pkt_data[111:64] = standard_metadata.ingress_global_timestamp;
          save_last_seen(pkt_data);
      }
  }
}
```

Il programma, una volta ricevuto un pacchetto, controlla se l'header IPv4 è valido e se non è presente l'header custom, in modo tale da poter processare il pacchetto.
Dopo aver processato il pacchetto, viene calcolato il numero di pacchetti ricevuti da entrambi i versi del flusso, e se la differenza  è maggiore della soglia, viene salvato nel registro THRASHOLDI  l'ultimo pacchetto ricevuto che ha causato il superamento della threashod.
Come detto in precedenza il registro THRESHOLDI è l'unione di 3 campi, due da 32 bit per gli indirizzi e uno da 48 per il timestamp, per un totale di 112 bit.
Questa struttura viene creata con la variabile pkt_data, che poi viene inizializzata con i valori degli indirizzi e del timestamp e salvata nel registro THRESHOLDI.

#### MyTunnel

Per quanto riguarda il traffico con header custom, il programma deve essere in grado di processare i pacchetti in arrivo, contare il numero di pacchetti nei flussi in modo tale da poter calcolare la soglia di traffico, e inoltrare i pacchetti in arrivo.

```c
action myTunnel_forward(egressSpec_t port) {
    standard_metadata.egress_spec = port;
    bit<112> pkt_data = 0x0;
    TRESHOLDI.read(pkt_data, 0);
    if(pkt_data != 0){
        hdr.myTunnel.IP_MAL = pkt_data[63:32];
        hdr.myTunnel.FLAG = 1;
    } 
}

table myTunnel_exact {
    key = {
        hdr.myTunnel.dst_id: exact;
    }
    actions = {
        myTunnel_forward;
        drop;
    }
    size = 1024;
    default_action = drop();
}

apply {
  
    ...

    if (hdr.myTunnel.isValid()) {
        // process tunneled packets
        myTunnel_exact.apply();
    }
}
```

Il programma, una volta ricevuto un pacchetto, controlla se l'header custom è valido, e se lo è, viene processato il pacchetto.
In particolare, viene letto il registro THRESHOLDI, e se il valore è diverso da 0 (quindi la soglia è stata raggiunta), viene inizializzato l'header custom con l'indirizzo IP del mittente del pacchetto che ha causato il superamento della soglia, e viene settato il flag a 1.
Il pacchetto viene poi inoltrato, settando il campo egress_spec con il valore della porta di uscita.

### Deparser

```c
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.ipv4);
    }
}
```

Il deparser è molto semplice, in quanto deve solo emettere i campi degli header che sono stati processati dal programma, nell'ordine corretto.

## Esecuzione e test manuale

Innanzitutto, una volta terminato il codice, eseguiamo il seguente comando per compilare i file sorgenti e avviare l'esecuzione della topologia:

```bash
make run
```

Dovrebbe così avviarsi la topologia con Mininet, con la quale possiamo interagire mediante l'opportuna console, per analizzare la topologia ad esempio. Noi andremo a digitare il seguente comando:

```bash
xterm h1 h2
```

Eseguito il comando, si apriranno due terminali, uno per ogni host della topologia specificato nel comando, quindi uno relativo all'host1 e il secondo relativo all'host2.

Non ci resta altro che eseguire lo script Python di ricezione su un'host a nostra scelta, che andrà quindi a rimanere in ascolto di messaggi indirizzati ad esso stesso.

```python
./mytunnel_receive.py
```

Sull'altro host invece, eseguiamo lo script per inviare un messaggio, specificando l'indirizzo IP dell'host destinazione (sul quale abbiamo avviato lo script di ricezione) e il messaggio da inviare. La porta di destinazione invece è impostata con il flag dst_id da settare per la porta del router da inviare.

```python
./mytunnel_send.py 10.0.1.1 "P4 is cool" --dst_id 1
```

Una volta eseguito anche questo script, riceveremo, in output, il seguente messaggio sull'host in ricezione, il quale riceverà il pacchetto e ne stamperà le informazioni a terminale.

```bash
got a packet

###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:01:01
  type      = 0x1212
###[ MyTunnel ]###
  pid       = 2048L
  dst_id    = 2L
  IP_MAL    = 0.0.0.0
  TIME      = 0L
  FLAG      = 0L
###[ IP ]###
  version   = 4L
  ihl       = 5L
  tos       = 0x0
  len       = 30
  id        = 1
  flags     = 
  frag      = 0L
  ttl       = 64
  proto     = hopopt
  chksum    = 0x63dd
  src       = 10.0.1.1
  dst       = 10.0.2.2
  \options   \
###[ Raw ]###
  load      = 'P4 is cool'
```

Al fine di far scattare la threshold, possiamo utilizzare il comando iperf, che ci permette di generare traffico di rete tra due host. Per farlo, eseguiamo il comando iperf in modalità server su un host.

```bash
iperf -s
```

Il client invece, eseguirà il comando iperf in modalità client, specificando l'indirizzo IP dell'host server.

```bash
iperf -c 10.0.1.1
```

Una volta eseguiti i due comandi, la threshold verrà superata, e quindi il pacchetto che ha causato il superamento verrà salvato nel registro THRESHOLDI, tutti i pacchetti successivi verranno inoltrati normalmente, mentre i pacchetti che usano il protocollo MyTunnel verranno modificati, in particolare il campo FLAG verrà settato a 1 e il campo IP_MAL verrà settato con l'indirizzo IP di destinazione del pacchetto che ha causato il superamento della threshold.
Per verificare che il pacchetto sia stato modificato, possiamo eseguire nuovamente lo script di ricezione, e verificare che il pacchetto ricevuto sia stato modificato.

```bash
./mytunnel_receive.py
```

Inviando il pacchetto con il comando:

```bash
./mytunnel_send.py 10.0.1.1 "P4 is cool" -
-dst_id 1
```

Riceveremo il seguente messaggio:

```bash
got a packet

###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:02:02
  type      = 0x1212
###[ MyTunnel ]###
     pid       = 2048L
     dst_id    = 1L
     IP_MAL    = 10.0.1.1
     TIME      = 0L
     FLAG      = 1L
###[ IP ]###
        version   = 4L
        ihl       = 5L
        tos       = 0x0
        len       = 30
        id        = 1
        flags     = 
        frag      = 0L
        ttl       = 64
        proto     = hopopt
        chksum    = 0x63dd
        src       = 10.0.2.2
        dst       = 10.0.1.1
        \options   \
###[ Raw ]###
           load      = 'P4 is cool'
```

Confrontando il pacchetto ricevuto con quello inviato, possiamo notare che il campo FLAG è stato settato a 1, mentre il campo IP_MAL è stato settato con l'indirizzo IP di destinazione del pacchetto che ha causato il superamento della threshold, quindi l'header custom è stato modificato correttamente, in relazione alle speciifche date.
