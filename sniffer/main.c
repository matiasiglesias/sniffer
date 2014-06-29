//
//  main.c
//  sniffer
//
//  Created by Matías Iglesias, Carla Santos y Diego Carabajal on 26/06/14.
//  Copyright (c) 2014 redes. All rights reserved.
//

#include "header.h"

int obtenerOpcion();
void obtenerEstadisticas();
void estadisticas(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
void interpretarCabeceras();
void mostrarHeaders(u_char *temp1,const struct pcap_pkthdr *header, const u_char *pkt_data);
int existeConexion(char *origen, char *destino, u_short puerto_origen, u_short puerto_destino);
void initConexiones();
int proxFlag(int pos);
void identificarConex(u_char *temp1,const struct pcap_pkthdr *header, const u_char *pkt_data);
void obtenerPrimerasConexiones();
void mostrarConexionesEncontradas();
void anchoDeBanda();
void liberarRecursos();
void mostrarConsumidores(u_char *temp1,const struct pcap_pkthdr *header, const u_char *pkt_data);
void mostrarTrafico();

void mostrarEstadisticas(int cant_paq, int cant_ip, int cant_tcp, int cant_udp, int cant_arp, int cant_rarp, int cant_otros);
void llenarFlag(int mascara, char arreglo[], int i, u_char TH_BANDERA);
void menu();
void mostrarHeaderTCP(const struct tdatagrama_tcp *tcp);
void mostrarHeaderUDP(const struct tdatagrama_udp *udp);
void mostrarConexiones(t_conexion tcpConex[], int cantConex, int pos);
void capturarTramas(char *argv[]);


int ip, arp, rarp, otros, ptcp, pudp, icmp;
int aplicaciones[100];
int cantidadA[100];		// aplicaciones conectadas
char *maquinas[100];	// ips conectadas
int cantidadM[100];		// paquetes por ip
int cantport;			// cantidad de puertos conectados
int cant_host;			// cantidad de ips conectadas
char * protoN[CANTIDAD_PROTOCOLOS] = {"ip","tcp","udp","arp","rarp", "icmp","otros"}; // protocolos
int opcion;
char errbuf[PCAP_ERRBUF_SIZE];
t_conexion tcpConex[MAX_CONEX];
int cant_paq, cant_ip, cant_arp, cant_tcp, cant_udp, cant_rarp, cant_otros, protocolo, posicion, conexEncontradas;
pcap_t *con;


int main(int argc, char *argv[]){
    if(argc != 3 && argc != 1){
        printf("Uso: ./sniffer <dispositivo> <cantidad de tramas> (MODO CAPTURA)\n");
		printf("            o bien:\n");
		printf("Uso: ./sniffer (MODO ANALISIS)\n");
		exit(0);
    }
	if(argc == 3)
		capturarTramas(argv);
	do{
		protocolo = 0;
		menu();
		opcion = obtenerOpcion();
		switch (opcion)		{
			case 1:
				obtenerEstadisticas();
				break;
			case 2:
				protocolo = TCP;
				interpretarCabeceras();
				break;
			case 3:
				protocolo = UDP;
				interpretarCabeceras();
				break;
			case 4:
				obtenerPrimerasConexiones();
				break;
			case 5:
			   	anchoDeBanda();
				mostrarTrafico();
				liberarRecursos();
				break;
		}
	}while (opcion != SALIR);
	printf("\n");
    
	return 0;
}


int obtenerOpcion(){
	char val[10];
    
	fgets(val, 10, stdin);
	return (atoi(val));
}


void obtenerEstadisticas(){
	pcap_t *p;
    
	cant_paq = 0;
	cant_ip = 0;
	cant_tcp = 0;
	cant_udp = 0;
	cant_arp = 0;
	cant_rarp = 0;
	cant_otros = 0;
    
	system("clear");
    
	if (!(p = pcap_open_offline("dump.txt", errbuf))) {//abre el archivo dump.txt (formato tcpdump)
		fprintf(stderr,"Error abriendo el fichero, %s, en modo lectura: %s\n", "dump.txt" , errbuf);
		exit(-1);
	}
    
	pcap_loop(p, 0, &estadisticas, (char *)0);//2º param en 0. Procesa hasta cond de finalización
	
	pcap_close(p);
	
	mostrarEstadisticas(cant_paq, cant_ip, cant_tcp, cant_udp, cant_arp, cant_rarp, cant_otros);
}

//genera las estadisticas del analizador.
void estadisticas(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
  	u_int i = 0;
  	tdatagrama_ip *datagrama;
  	ttrama_ethernet *trama;
	struct protoent *es_protocolo;
    
	trama = (ttrama_ethernet *)(pkt_data);
	cant_paq++;
    
  	if(ntohs(trama->tipo)== ETHERTYPE_IP){
		cant_ip++;
    	datagrama = (tdatagrama_ip *)(pkt_data + sizeof(ttrama_ethernet));
		es_protocolo = getprotobynumber(datagrama->protocolo);
  		if(es_protocolo != 0){
			if ( (strcmp(es_protocolo->p_name, "tcp")) == 0 )
				cant_tcp++;
			else
				if( (strcmp(es_protocolo->p_name, "udp")) == 0)
					cant_udp++;
  		}
	}
	else
		if(ntohs(trama->tipo) == ETHERTYPE_ARP){
			cant_arp++;
        }
		else
			if(ntohs(trama->tipo) == ETHERTYPE_REVARP){
				cant_rarp++;
            }
			else {
				cant_otros++;
            }
}


//Interpreta las cabeceras de los paquetes leidos
void interpretarCabeceras(){
	pcap_t *p;
    
	cant_paq = 1;
	system("clear");
	if (!(p = pcap_open_offline("dump.txt", errbuf))) {
		fprintf(stderr,"Error abriendo el fichero, %s, en modo lectura: %s\n", "dump.txt" , errbuf);
		exit(-1);
	}
    
	pcap_loop(p, 0, &mostrarHeaders, (char *)0);
    
	pcap_close(p);
	printf("\n\n Presione enter para continuar...");
	getchar();
}


void mostrarHeaders(u_char *temp1,const struct pcap_pkthdr *header, const u_char *pkt_data){
  	tdatagrama_ip *datagrama;
  	ttrama_ethernet *trama;
	struct protoent *es_protocolo;
	const struct tdatagrama_tcp *tcp;
	const struct tdatagrama_udp *udp;
	const char *payload;
	int size_ip;
	int size_tcp;
	int size_udp;
    
	cant_paq++;
    
	trama = (ttrama_ethernet *)(pkt_data);
    
	//si es una trama ethernet e indica que el protocolo es IP
  	if(ntohs(trama->tipo) == ETHERTYPE_IP){//The function converts the unsigned short integer netshort from network byte order to host byte order.
        
		//genero el datagrama que contiene los datos de la trama capturada
        datagrama = (tdatagrama_ip *)(pkt_data + sizeof(ttrama_ethernet));
        
		//es_protocolo = getprotobynumber(datagrama->protocolo);
		
		size_ip = IP_HL(datagrama)*4;
		if (size_ip < 20) {
			printf("   * Longitud del Header IP invalida: %u bytes\n", size_ip);
			return;
		}
        
		if ( ( (protocolo == TCP) && (datagrama->protocolo == IPPROTO_TCP)) || ( (protocolo == UDP) && (datagrama->protocolo == IPPROTO_UDP) ) ){
			printf("\n      Numero de Trama: %d\n", cant_paq);
			//imprimo la IP de origen y destino de la trama capturada
			printf("           IP Origen: %s\n", inet_ntoa(datagrama->dir_origen));
			printf("           IP Destino: %s\n", inet_ntoa(datagrama->dir_destino));
            
			//identifico el tipo de protocolo de la trama capturada
			switch(datagrama->protocolo){
				case IPPROTO_TCP:
					printf("      Protocolo: TCP\n\n");
					break;
				case IPPROTO_UDP:
					printf("      Protocolo: UDP\n\n");
					break;
				case IPPROTO_ICMP:
					printf("      Protocolo: ICMP\n\n");
					return;
				case IPPROTO_IP:
					printf("      Protocolo: IP\n\n");
					return;
				default:
					printf("      Protocolo: (?)\n\n");
					return;
			}
            
		}
		if ( protocolo == TCP && datagrama->protocolo == IPPROTO_TCP){
			tcp = (struct tdatagrama_tcp*)(pkt_data + SIZE_ETHERNET + size_ip);
            
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Longitud del Header TCP invalida: %u bytes\n", size_tcp);
				return;
			}
            
			mostrarHeaderTCP(tcp);
		}
		else{
			if ( protocolo == UDP && datagrama->protocolo == IPPROTO_UDP ){
				udp = (struct tdatagrama_udp*)(pkt_data + SIZE_ETHERNET + size_ip);
				size_udp = (int) udp;
                
				if (size_udp < 20){
					printf("   * Longitud del Header UDP invalida: %u bytes\n", size_udp);
					return;
				}
                
				mostrarHeaderUDP(udp);
			}
		}
        
	}
}

int existeConexion (char *origen, char *destino, u_short puerto_origen, u_short puerto_destino)
{
	int i;
	char ipOrigen[20], ipDestino[20];
    
	for (i = 0; i < MAX_CONEX; i++)	{
		if ( (tcpConex[i].ocupado) == 1){
			strcpy(ipOrigen, (tcpConex[i].ip_origen));
			strcpy(ipDestino, (tcpConex[i].ip_destino));
            
			if ( (( strcmp(origen, ipOrigen ) == 0) && (strcmp(destino, ipDestino) == 0) ) || ((strcmp(destino, ipOrigen) == 0) && (strcmp(origen, ipDestino) == 0)) ){
                if ((tcpConex[i].port_origen == puerto_origen && tcpConex[i].port_destino == puerto_destino) ||
                    (tcpConex[i].port_origen == puerto_destino && tcpConex[i].port_destino == puerto_origen))
                    return i;
			}
		}
		else{
			break;
		}
	}
    
	return (-1);
}


//inicializa la estrucura que analizara las conexiones.
void initConexiones(){
	int i;
    
	for (i = 0; i < MAX_CONEX; i++)	{
		tcpConex[i].data = NULL;
	    tcpConex[i].ocupado = 0;
		tcpConex[i].syn = 0;
		tcpConex[i].ack_syn = 0;
		tcpConex[i].ack1 = 0;
		tcpConex[i].fin = 0;
		tcpConex[i].ack_fin = 0;
		tcpConex[i].ack2 = 0;
	}
}


int proxFlag(int pos){
	if (tcpConex[pos].data != NULL)	{
		//si tengo que mirar el bit de SYN
		if (tcpConex[pos].syn == 0)
			return SYN;
		//si tengo que mirar el bit de ACK+SYN
		if (tcpConex[pos].ack_syn == 0)
			return ACK_SYN;
		//si tengo que mirar el bit de ACK1
		if (tcpConex[pos].ack1 == 0)
			return ACK1;
		//si tengo que mirar el bit de FIN
		if (tcpConex[pos].fin == 0)
			return FIN;
		//si tengo que mirar el bit de ACK+FIN
		if (tcpConex[pos].ack_fin == 0)
			return ACK_FIN;
		//si tengo que mirar el bit de ACK2
		if (tcpConex[pos].ack2 == 0)
			return ACK2;
	}
	return (-1);
}


//toma un paquete y lo analiza para ver los valores que tiene
void identificarConex(u_char *temp1,const struct pcap_pkthdr *header, const u_char *pkt_data){
  	tdatagrama_ip *datagrama;
  	ttrama_ethernet *trama;
	struct protoent *es_protocolo;
	const struct tdatagrama_tcp *tcp;
	int pos, prox_param;
	int size_ip;
	int mask, flag;
	char origen[20], destino[20];
    
	pos = 0;
	trama=(ttrama_ethernet *)(pkt_data);
    
	//si ya encontre 2 conexiones completas
	if (conexEncontradas == 2){
		pcap_breakloop(con);
		return;
	}
    
	//si se trata de una trama ethernet
  	if(ntohs(trama->tipo)== ETHERTYPE_IP){
		//genero el datagrama que contiene los datos de la trama capturada
        datagrama = (tdatagrama_ip *)(pkt_data+sizeof(ttrama_ethernet));
		
		//si el datagrama capturado es tcp, lo proceso
		if ( (datagrama->protocolo) == IPPROTO_TCP){
			size_ip = IP_HL(datagrama)*4; // tomo el tamaño de la cabecera de IP = 20 bytes.
			tcp = (struct tdatagrama_tcp*)(pkt_data + SIZE_ETHERNET + size_ip);
            
			//aplico la mascara solo para filtrar aquellos paquetes que esten intentando establecer una conexion
			mask = ACK_SYN_FLAG;
			flag = tcp->th_flags & mask;
            
			strcpy(origen, inet_ntoa(datagrama->dir_origen));
			strcpy(destino, inet_ntoa(datagrama->dir_destino));
            
			//si no me vino un syn acompañada de un ack
			if (flag != ACK_SYN_FLAG){
				mask = SYN_FLAG;
				flag = tcp->th_flags & mask;
				
				//si lo que me vino es un syn solo
				if (flag == SYN_FLAG){
					//si las direcciones ip no existen, la añado
					if ( (pos = existeConexion(origen, destino, tcp->th_sport, tcp->th_dport)) == -1 ){
                        
						tcpConex[posicion].data = datagrama;
						tcpConex[posicion].ocupado = 1;
						strcpy(tcpConex[posicion].ip_origen , origen);
						strcpy(tcpConex[posicion].ip_destino , destino);
                        
						tcpConex[posicion].port_origen = tcp->th_sport;
						tcpConex[posicion].port_destino = tcp->th_dport;
						
						if (posicion < MAX_CONEX)
							posicion++;
					}
				}
			}
            
            
			pos = existeConexion(origen, destino, tcp->th_sport, tcp->th_dport);
			
			//si tengo una posicion valida
			if (pos != -1){
				prox_param = proxFlag(pos);
                
				if (prox_param != -1){
					switch (prox_param){
						case SYN:
							mask = SYN_FLAG;
							mask = tcp->th_flags & mask;
						 	if (mask == SYN_FLAG)
								tcpConex[pos].syn = 1;
						  	break;
                            
						case ACK_SYN:
						 	mask = ACK_SYN_FLAG;
						  	mask = tcp->th_flags & mask;
						  	if (mask == ACK_SYN_FLAG)
								tcpConex[pos].ack_syn = 1;
						  	break;
                            
						case ACK1:
						  	mask = ACK1_FLAG;
						  	mask = tcp->th_flags & mask;
						 	if (mask == ACK1_FLAG)
								tcpConex[pos].ack1 = 1;
						  	break;
                            
						case FIN:
							mask = FIN_FLAG;
							mask = tcp->th_flags & mask;
							if (mask == FIN_FLAG)
								tcpConex[pos].fin = 1;
							break;
                            
                            
						case ACK_FIN:
							mask = ACK_FIN_FLAG;
							mask = tcp->th_flags & mask;
							if (mask == ACK_FIN_FLAG)
								tcpConex[pos].ack_fin = 1;
							break;
                            
                            
						case ACK2:
							mask = ACK2_FLAG;
							mask = tcp->th_flags & mask;
							if (mask == ACK2_FLAG){
								tcpConex[pos].ack2 = 1;
								tcpConex[pos].completo = 1;
								tcpConex[pos].port_origen = tcp->th_sport;
								tcpConex[pos].port_destino = tcp->th_dport;
								conexEncontradas++;
							}
						   	break;
					}
				}
			}
		}
	}
}

//muestras las ip de la conexiones que iniciaron y finalizaron una conexion
void mostrarConexionesEncontradas(){
	int i;
	int cantConex;
	tdatagrama_ip datagrama;
	
	if (conexEncontradas == 1 )	{
        printf("\n   Se encontro %d conexion que inicio y finalizo correctamente.\n", conexEncontradas);
        printf("\n   La conexion fue:\n");
	}
	else{
        printf("\n   Se encontraron %d conexiones que se iniciaron y finalizaron correctamente.\n", conexEncontradas);
        printf("\n   Las primeras dos conexiones fueron:\n");
	}
	
	for (i = 0, cantConex = 1; i < MAX_CONEX; i++){
		//si la posicion que estoy mirando me indica que se inicio y finalizo correctamente una conexion
		if (tcpConex[i].completo == 1){
			//imprimo la IP de origen y destino de la trama capturada
			mostrarConexiones(tcpConex, cantConex, i);
			cantConex++;
		}
	}
	printf("\n");
}

//obtiene las 2 primeras conexiones que comenzaron y finalizaron correctamente.
void obtenerPrimerasConexiones(){
	//inicializo la lista de conexiones.
	initConexiones();
	posicion = 0;
	conexEncontradas = 0;
	system("clear");
	//trato de abrir el archivo dump
	if (!(con = pcap_open_offline("dump.txt", errbuf))) {
		fprintf(stderr,"Error abriendo el fichero, %s, en modo lectura: %s\n", "dump.txt" , errbuf);
		exit(-1);
	}
    
	//leo del archivo dump
	pcap_loop(con, 0, &identificarConex, (char *)0);
	//cerramos el dispositivo de captura y la memoria usada por el descriptor.
	pcap_close(con);
	if ((conexEncontradas > 0) && (conexEncontradas <= 2)){
		mostrarConexionesEncontradas();
	}
	else{
		printf("\nNo se encontraron conexiones que iniciaron y finalizaron correctamente.\n");
		printf("\nCantidad de conexiones encontradas: %d\n", conexEncontradas);
	}
	printf("\n\n Presione enter para continuar...");
	getchar();
}

void liberarRecursos(){
	int i;
    
	for (i = 0; i < 100; i++){
        if(maquinas[i] != NULL){
            free(maquinas[i]);
            maquinas[i] = NULL;
            cantidadM[i] = 0;
            cant_host = 0;
        }
	}
    
}

void anchoDeBanda(){
	pcap_t *p;
	int i;
    
	cant_paq = 1;
	for (i=0; i<100;i++){
		aplicaciones[i]=-1;
	}
	cant_host = 0;
	cantport = 0;
	protocolo = TCP;
	ip = 0;
	arp = 0;
	rarp = 0;
	icmp = 0;
	otros = 0;
	pudp = 0;
	ptcp = 0;
    
	system("clear");
	if (!(p = pcap_open_offline("dump.txt", errbuf))) {
		fprintf(stderr,"Error abriendo el fichero, %s, en modo lectura: %s\n", "dump.txt" , errbuf);
		exit(-1);
	}
	pcap_loop(p, 0, &mostrarConsumidores, (char *)0);
	pcap_close(p);
}


//muestra los consumidores
void mostrarConsumidores(u_char *temp1,const struct pcap_pkthdr *header, const u_char *pkt_data){
  	tdatagrama_ip *datagrama;
  	ttrama_ethernet *trama;
	const struct tdatagrama_tcp *tcp;
	const struct tdatagrama_udp *udp;
	int size_ip;
	int size_tcp;
	int size_udp;
	int i;
    char origen[20], destino[20];
	long sport, dport; 	//  sport => puerto origen  y  dport => puerto destino
	
	trama = (ttrama_ethernet *)(pkt_data);
    
	//si se trata de una trama ethernet
  	if(ntohs(trama->tipo) == ETHERTYPE_IP){
		ip++;
        datagrama = (tdatagrama_ip *)(pkt_data+sizeof(ttrama_ethernet));
		size_ip = IP_HL(datagrama)*4;
		if (size_ip < 20){
			printf("   * Longitud del Header IP invalida: %u bytes\n", size_ip);
			return;
		}
        
		strcpy(origen,inet_ntoa(datagrama->dir_origen));
		strcpy(destino,inet_ntoa(datagrama->dir_destino));
        
        
		for (i = 0; i < 100; i++){
			if(maquinas[i] == NULL){
                maquinas[i] = (char*)malloc(20 * sizeof(char));
				strcpy(maquinas[i],origen);
				cantidadM[i] = 1;
				cant_host++;
				break;
			}
			else{
		        if(strcmp(maquinas[i],origen) == 0)	{
					cantidadM[i]++;
					break;
				}
			}
            
	    }
        
		for (i = 0; i < 100; i++){
			if(maquinas[i] == NULL)	{
                maquinas[i] = (char*)malloc(20 * sizeof(char));
				strcpy(maquinas[i],destino);
				cantidadM[i] = 1;
				cant_host++;
				break;
			}
			else{
			    if(strcmp(maquinas[i], destino)== 0){
					cantidadM[i]++;
					break;
				}
			}
	 	}
        
		//identifico el tipo de protocolo de la trama capturada
		switch(datagrama->protocolo){
			case IPPROTO_TCP:
				ptcp++;
				break;
			case IPPROTO_UDP:
				pudp++;
				break;
			case IPPROTO_ICMP:
				icmp++;
				return;
			default:
				otros++;
				return;
		}
        
		
		if ( protocolo == TCP && datagrama->protocolo == IPPROTO_TCP){
			tcp = (struct tdatagrama_tcp*)(pkt_data + SIZE_ETHERNET + size_ip);
            
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Longitud del Header TCP invalida: %u bytes\n", size_tcp);
				return;
			}
            sport = ntohs(tcp->th_sport);
            dport = ntohs(tcp->th_dport);
  		}
		else{	// El Protocolo es UDP
			udp = (struct tdatagrama_udp*)(pkt_data + SIZE_ETHERNET + size_ip);
			sport = ntohs(udp->th_sport);
			dport = ntohs(udp->th_dport);
		}
        
        for (i = 0; i < 100; i++){
			if(aplicaciones[i] == -1){
				aplicaciones[i] = sport;
				cantidadA[i] = 1;
				cantport++;
				break;
			}
            if(aplicaciones[i] == sport){
				cantidadA[i]++;
				break;
			}
		}
        
		for (i = 0; i < 100; i++){
			if(aplicaciones[i] == -1){
				aplicaciones[i] = dport;
				cantidadA[i] = 1;
				cantport++;
				break;
			}
            if(aplicaciones[i] == dport){
				cantidadA[i]++;
				break;
			}
		}
        
	}
}


void ordenarArreglo(int original[], int copia[], int tope){
	int i, j, aux, m, ant;
	
    
	for (j = 0; j < tope; j++){
		copia[j] = original[j];
	}
    
	for (j = 0; j < tope-1; j++){
		for (i = 0; i < tope-1 ; i++){
            if(copia[i] < copia[i+1]){
                aux = copia[i];
				copia[i] = copia[i+1];
                copia[i+1] = aux;
			}
		}
	}
}


// Muestra los datos de los arreglos que recibe por parametro
void mostrarDatosArreglo(int original[], int copia[], int tope, int tipo){
	int i, j, aux, m, ant;
	int pepe;
	
	m = 0;
	ant = -1;
    // Muestra las 5 Aplicaciones con mas Trafico(de mayor a menor).
    for (i = 0; i < 5 && i < tope; i++)	{
		aux = copia[i];
		//	si el arreglo de las Aplicaciones no est vacio.
		if(aux != ant)
			m = 0;
		for (j = m; j < tope; j++){
			if(original[j] == aux){
				ant = aux;
				m = j+1;
				break ;
			}
		}
		//printf("  antes del switch   TIPO  3   : %d\n", tipo);
        switch (tipo){
			case 1:
				printf( "            Aplicacion %d\n", aplicaciones[j]);
				break;
			case 2:
				printf( "            Maquina %s\n", maquinas[j]);
				break;
                
			case 3:
				if (copia[i] != 0)
                    printf( "            Protocolo %s\n", protoN[j]);
				break;
		}
	}
	printf("\n");
}


//muestra el trafico en la red.
void mostrarTrafico(){
	int cantidadAux[100], cantidadAux2[100];
	int protoaux[CANTIDAD_PROTOCOLOS];
	//arreglo que contiene los nombres de los protocolos mas usados
	int proto[CANTIDAD_PROTOCOLOS] = {ip, ptcp, pudp, arp, rarp, icmp, otros};
	
    
    //------------------------------- MUESTRO LAS APLICACIONES ----------------------------------------
    printf("*****************************************************\n");
	printf("* Puertos de las aplicaciones con mas trafico       *\n");
	printf("*****************************************************\n\n");

	ordenarArreglo(&cantidadA[0], &cantidadAux[0], cantport);
	mostrarDatosArreglo(&cantidadA[0], &cantidadAux[0], cantport, 1);
	
    //------------------------------- MUESTRO LAS MAQUINAS ----------------------------------------
    
    printf("*****************************************************\n");
	printf("* IP de las maquinas que tuvieron mas trafico       *\n");
	printf("*****************************************************\n\n");

	ordenarArreglo(&cantidadM[0], &cantidadAux2[0], cant_host);
	mostrarDatosArreglo(&cantidadM[0], &cantidadAux2[0], cant_host, 2);
	
    //------------------------------- MUESTRO LOS PROTOCOLOS ----------------------------------------
	
	printf("*****************************************************\n");
	printf("* Nombres de los protocolos con mas trafico         *\n");
	printf("*****************************************************\n");

	ordenarArreglo(&proto[0], &protoaux[0], CANTIDAD_PROTOCOLOS);
	mostrarDatosArreglo(&proto[0], &protoaux[0], CANTIDAD_PROTOCOLOS, 3);
    
	//salgo de la funcion, a la espera de que el usuario presione una tecla
	printf("\nPresione enter para continuar...");
	getchar();
}

//muestra la pantalla de seleccion de opciones
void menu(){
    
    system("clear");
    printf("\n*****************************************************\n");
    printf("*                                                   *\n");
	printf("*  Trabajo Practico Nro. 3 - Analizador de trafico  *\n"); 
    printf("*                                                   *\n");
    //printf("*           Iglesias, Carabajal, Santos             *\n");
    printf("*****************************************************\n");
    printf("*                                                   *\n");
    printf("* 1 - Estadisticas		                    *\n");
    printf("*                                                   *\n");
    printf("* 2 - Filtrado de paquetes TCP	      	            *\n");
    printf("*                                                   *\n");
    printf("* 3 - Filtrado de paquetes UDP		            *\n");
    printf("*                                                   *\n");
    printf("* 4 - Primeras dos conexiones TCP		    *\n");
	printf("*                                                   *\n");
    printf("* 5 - Ancho de Banda				    *\n");
    printf("*                                                   *\n");
    printf("* 6 - Salir				            *\n");
    printf("*                                                   *\n");
	printf("*****************************************************\n");

    printf("\n\nIngrese la opcion: ");
}

void mostrarEstadisticas(int cant_paq, int cant_ip, int cant_tcp, int cant_udp, int cant_arp, int cant_rarp, int cant_otros)
{
	
	printf("\n**************************************************************\n");

	printf("\n        Estadisticas de protocolos destacados\n");

    printf("\n**************************************************************\n");

	printf("\n	Cantidad total de paquetes capturados:..... %d\n", cant_paq);
    
	printf("	Cantidad paquetes ARP: .................... %d\n", cant_arp);
    
	printf("	Cantidad paquetes RARP: ................... %d\n", cant_rarp);
    
	printf("	Cantidad paquetes OTROS protocolos: ....... %d\n", cant_otros);
    
	printf("	Cantidad paquetes IP:...................... %d\n", cant_ip);
    
	printf("	Cantidad paquetes IP de TCP:............... %d\n", cant_tcp);
    
	printf("	Cantidad paquetes IP de UDP:............... %d\n", cant_udp);
    
    printf("\n**************************************************************\n");

	printf("\n\n  Presione enter para continuar...");
	getchar();
    
}

void mostrarHeaderTCP(const struct tdatagrama_tcp *tcp)
{
    
    char flags[8];
    int mask;
    
	
	flags[0]='0';
	flags[1]='0';
    
	mask = tcp->th_flags & TH_URG;
	llenarFlag(mask, &flags[0], 2, TH_URG);
	
	mask = tcp->th_flags & TH_ACK;
	llenarFlag(mask, &flags[0], 3, TH_ACK);
    
	mask = tcp->th_flags & TH_PUSH;
	llenarFlag(mask, &flags[0], 4, TH_PUSH);
	
	mask = tcp->th_flags & TH_RST;
	llenarFlag(mask, &flags[0], 5, TH_RST);
	
	mask = tcp->th_flags & TH_SYN;
	llenarFlag(mask, &flags[0], 6, TH_SYN);
    
	mask = tcp->th_flags & TH_FIN;
	llenarFlag(mask, &flags[0], 7, TH_FIN);
    
	flags[8]= '\0';
	
    
    printf("      0              7                15              23             31\n");
    printf("      +--------Puerto origen----------+---------Puerto destino--------+\n");
    printf("      |           %-20d|               %-16d|\n", ntohs(tcp->th_sport),ntohs(tcp->th_dport));
    printf("      +---------------------Numero de Secuencia-----------------------+\n");
    printf("      |                             %-34d|\n", ntohs(tcp->th_seq));
    printf("      +-------------------Numero de reconocimiento--------------------+\n");
    printf("      |                             %-34d|\n", ntohs(tcp->th_ack));
    printf("      +-----xxxx----+-----Flags-------+-----------Ventana-------------+\n");
    printf("      |      %-7d|     %-12s|             %-18d|\n", 0, flags, ntohs(tcp->th_win));
    printf("      +---------URG------ACK------PUSH------RST------SYN-------FIN----+\n");
    printf("      | %c %c  |   %c    |   %c   |    %c    |    %c    |   %c    |    %c     |\n",flags[0],flags[1],flags[2],flags[3],flags[4],flags[5],flags[6],flags[7]);
    printf("      +----------checksum-------------+-------Puntero urgente---------+\n");
    printf("      |             %-18d|              %-17d|\n", ntohs(tcp->th_sum),ntohs(tcp->th_urp));
    printf("      +---------------------------------------------------------------+\n");
    
}

void llenarFlag(int mascara, char arreglo[], int i, u_char TH_BANDERA){
 	if (mascara == TH_BANDERA){
		arreglo[i]='1';
	}
	else{
		arreglo[i]='0';
	}
}

void mostrarHeaderUDP(const struct tdatagrama_udp *udp){
    
    printf("      0              7                15              23             31\n");
    printf("      +--------Puerto origen----------+---------Puerto destino--------+\n");
    printf("      |             %-18d|              %-17d|\n", ntohs(udp->th_sport),ntohs(udp->th_dport));
    printf("      +-----Longitud del mensaje------+----------Checksum-------------+\n");
    printf("      |             %-18d|             %-18d|\n", ntohs(udp->th_long),ntohs(udp->th_sum));
    printf("      +---------------------------------------------------------------+\n");
    
}

void mostrarConexiones(t_conexion tcpConex[], int cantConex, int pos){
    //imprimo la IP de origen y destino de la trama capturada
    printf("\n	  	  %dº Conexion\n", cantConex);
    printf("     --------------------------------------------------------------------------\n");
    printf("           IP Origen:   %s     	   Puerto Origen:   %d\n", (tcpConex[pos].ip_origen),ntohs(tcpConex[pos].port_origen));
    printf("           IP Destino:  %s   	   Puerto Destino:  %d\n", (tcpConex[pos].ip_destino),ntohs(tcpConex[pos].port_destino));
}


//capturador de paquetes
void capturarTramas(char *argv[]){
   	char *interface_de_red;
    char errbuf[PCAP_ERRBUF_SIZE];
	
	// manejador de la interfaz elegida
    pcap_t *p;
	// file descriptor del archivo dump
	pcap_dumper_t *pcap_fd;
	int cant_paquetes;
    
    
	//dispositivo al cual me conecto para capturar los paquetes
	interface_de_red = argv[1];//interfaz tal comoeth0, wlan0, etc...
    
	//activo el dispositivo para caturar los paquetes
    p = pcap_open_live(interface_de_red, BUFSIZ, 1, 0, errbuf);
    
	//si no pude abrir el dispositivo para capturar paquetes, muestro error...
    if(p == NULL){ 
		printf("ERROR en pcap_open_live(): %s\n",errbuf); 
		exit(-1); 
    }
    
	//creo el archivo temporal que contendra el flujo de datos capturado.	
	if ( (pcap_fd = pcap_dump_open(p, "./dump.txt")) == NULL ){
		printf("Error al tratar de abrir el archivo para realizar el volcado de paquetes\n");
		exit(-1);
	}	
	
	cant_paquetes = atoi(argv[2]); //Convierte la cadena apuntada a una representación de int.
	//si la cantidad de paquetes a capturar es menor o igual a cero
	//le asigno un valor por defecto
	if ( cant_paquetes <= 0 )
	    cant_paquetes = CANTIDAD_DEFAULT_PAQUETES;
    
	printf("Realizando captura de paquetes, por favor espere...\n");
	
    pcap_loop(p, cant_paquetes, &pcap_dump, (char *)pcap_fd); //procesa paquetes hasta que todos los paquetes de
    													      //de cant_paquetes hayn sido procesados		
	pcap_dump_close(pcap_fd);
	pcap_close(p);
}
