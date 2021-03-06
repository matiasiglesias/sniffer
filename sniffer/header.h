#include <pcap.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>


// Protocolos
#define TCP 			1
#define UDP 			2


// Comandos
#define ESTADISTICAS 		1
#define FILTRAR_TCP 		2
#define FILTRAR_UDP 		3
#define ID_CONEXION 		4
#define ID_CONS_ANCHO_B 	5
#define SALIR 			6


#define SIZE_ETHERNET 14
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

#define ETHERTYPE_IP 		0x0800
#define ETHERTYPE_ARP 		0x0806
#define ETHERTYPE_REVARP 	0x8035

#define LINE_LEN 16

/* Tamaño de las direcciones Ethernet */
#define ETHER_ADDR_LEN		6


#define MAX_CONEX 		100

/* Banderas para establecer la conexion TCP  */
#define SYN_FLAG		0x02
#define ACK_SYN_FLAG	0x12
#define ACK1_FLAG		0x10
/********************************************/

/* Banderas para cerrar la conexion TCP     */
#define FIN_FLAG		0x01
#define ACK_FIN_FLAG	0x11
#define ACK2_FLAG		0x10
/********************************************/

#define SYN				1
#define ACK_SYN			2
#define ACK1			3
#define FIN				4
#define ACK_FIN			5
#define ACK2			6

//cantidad de paquetes a capturar por defecto
#define CANTIDAD_DEFAULT_PAQUETES	10

#define CANTIDAD_PROTOCOLOS	7

/* ------------- ESTRUCTURAS DE PAQUETES -------------- */


/* CABECERA IP */
typedef struct 
{
	unsigned char ip_vhl; 				/* 4 bits version, 4 bits longitud de cabecera */
 	unsigned char tos; 				/* Tipo de servicio */
  	unsigned short longitud; 			/* longitud total del datagrama */
  	unsigned short id; 				/* Identificacion */
  	unsigned short indicadores_despfragmento; 	/* 3 bits de indicadores, 13 bits de fragmento */
  	unsigned char ttl; 				/* Tiempo de vida */
  	unsigned char protocolo; 			/* protocolo */
  	unsigned short suma; 				/* Suma de comprobacion (checksum) de la cabecera 2 BYTES */
  	struct  in_addr dir_origen,dir_destino;  	/* direcciones origen y destino. */ 
  	unsigned int opciones_relleno; 			/* 24 bits opciones y 8 de relleno */
  	unsigned char *datos;				/* DATOS */
} tdatagrama_ip;



/* CABECERA ETHERNET */
typedef struct {
        u_char  direccion_origen[ETHER_ADDR_LEN];  	/* direccion origen */
        u_char  direccion_destino[ETHER_ADDR_LEN]; 	/* direccion destino */
        u_short tipo;  	                  		/* Tipo: IP-ARP-RARP-etc */
}ttrama_ethernet;


/* CABECERA TCP */
typedef u_int tcp_seq;

struct tdatagrama_tcp 
{
	u_short th_sport;               /* puerto origen */
	u_short th_dport;               /* puerto destino */
	tcp_seq th_seq;                 /* numero de secuencia */
	tcp_seq th_ack;                 /* ack */
	u_char  th_offx2;               /* offset datos, reservado */
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	//#define TH_ECE  0x40
	//#define TH_CWR  0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG/*|TH_ECE|TH_CWR*/)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* puntero a urgente */
};


/* CABECERA UDP */
typedef u_int udp_seq;

struct tdatagrama_udp 
{
        u_short th_sport;               /* puerto origen */
        u_short th_dport;               /* puerto destino */
        u_short th_long;                /* longitud del mensaje */
        u_short th_sum;                 /* checksum */
};

// Paquete a nivel de Capa de Enlace.
typedef struct
{
	tdatagrama_ip *data;		//contiene los datos del datagrama capturado
	int ocupado;			//marca a la estructura si ya fue visitada o no
	char ip_origen[18];		//guarda la dir ip de origen
	u_short port_origen;            /* puerto origen */
    u_short port_destino;           	/* puerto destino */
	char ip_destino[18];		//guarda la dir ipd el destino
	int syn;			//marca si la estructura ha recibido la bandera de syn
	int ack_syn;			//marca si la estructura ha recibido  ack + syn
	int ack1;			//marca si la estructura ha recibido ack del syn
	int fin;			//marca si la estructura ha recibido la bandera de fin
	int ack_fin;			//marca si la estructura ha recibido ack + fin
	int ack2;			//marca si la estructura ha recibido ack del fin
	int completo;			//marca si la estructura ha comenzado y finalizado correctamente.
} t_conexion;
