import asyncio
import re
import time
from grader.tcputils import FLAGS_ACK, FLAGS_FIN, MSS, calc_checksum, fix_checksum, make_header, read_header
from tcputils import *
import math

ALPHA = 0.125
BETA = 0.25


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no)
            flags = FLAGS_SYN + FLAGS_ACK
            ack_no = seq_no + 1
            
            self.rede.enviar(fix_checksum(make_header(dst_port, src_port, seq_no, ack_no, flags), src_addr, dst_addr), src_addr)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.seq_envio = ack_no
        self.expected_seq_no = seq_no + 1
        self.callback = None
        self.sendbase = 0
        self.start = time.time()
        self.end = time.time()
        self.reenvio = False
        self.sampleRTT = 0.0
        self.estimatedRTT = -1
        self.devRTT = -1
        self.timeoutInterval = 1
        self.timer = None
        self.pending_segments = []
        self.pending_segments_payload = []
        self.window_size = 1*MSS
        self.rcv_window_size = 0
        self.buffer = []
        self.buffer_payload = []

    def _exemplo_timer(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3]
    
        if len(self.pending_segments) > 0:
            self.window_size = ((self.window_size//MSS)//2)*MSS
            self.servidor.rede.enviar(fix_checksum(self.pending_segments[0], src_addr, dst_addr), src_addr)
            self.reenvio = True
        
    def _set_timer_info(self, segment, tam_payload):
        self.pending_segments.append(segment)
        self.pending_segments_payload.append(tam_payload)

    def _calc_rtt(self):
        self.end = time.time()
        connect_ack = True if self.sampleRTT <= 0 else False
        self.sampleRTT = self.end - self.start
    
        if connect_ack:
            self.estimatedRTT = self.sampleRTT
            self.devRTT = self.sampleRTT/2
        else: 
            self.estimatedRTT = (1 - ALPHA)*self.estimatedRTT + ALPHA*self.sampleRTT
            self.devRTT = (1 - BETA)*self.devRTT + BETA*abs(self.sampleRTT - self.estimatedRTT)
        self.timeoutInterval = self.estimatedRTT + 4.0*self.devRTT

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):

        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3]
        
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.callback(self, b'')
            flags = FLAGS_ACK
            self.ack_no = seq_no + 1
            self.servidor.rede.enviar(fix_checksum(make_header(dst_port, \
                    src_port, self.seq_no, self.ack_no, flags), src_addr, \
                         dst_addr), src_addr)
        elif self.expected_seq_no == seq_no:
            dados = payload
            self.expected_seq_no += len(payload)
            self.ack_no = seq_no + len(payload)
            if len(dados) > 0:
                if (self.callback):
                    self.callback(self, dados)
                flags = FLAGS_ACK
                self.servidor.rede.enviar(fix_checksum(make_header(dst_port, \
                    src_port, self.seq_no + 1, self.ack_no, flags), src_addr, \
                         dst_addr), src_addr)

            
            if len(self.pending_segments) > 0 and not self.reenvio:
                self._calc_rtt() 
            if ack_no > self.sendbase:
                aux = self.sendbase
                self.sendbase = ack_no
                if self.timer is not None:
                    self.timer.cancel()
                if len(self.pending_segments) > 0:
                    while aux < ack_no and len(self.pending_segments) > 0:
                        variavel = self.pending_segments_payload.pop(0)
                        self.pending_segments.pop(0)
                        self.rcv_window_size += variavel
                        aux += variavel
                    if self.window_size <= self.rcv_window_size: 
                        self.window_size += MSS 
                        self.rcv_window_size = 0
                    self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._exemplo_timer)
                    if len(self.buffer) > 0:
                        self.enviar('👍', True)
            self.reenvio = False        

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados, rest = False):
        """
        Usado pela camada de aplicação para enviar dados
        """

        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3]

        self.start = time.time()
        if not rest:
            if not self.reenvio:
                if len(dados) >= MSS:
                    i = 0
                    max_it = math.ceil((1.0*len(dados)) / MSS)
                    self.sendbase = self.seq_no + 1
                    while i < max_it:
                        flags = FLAGS_ACK
                        segment = make_header(dst_port, src_port, self.seq_no + 1, self.ack_no, flags)
                        payload = dados[MSS*i:MSS*(i+1)]
                        self.seq_no += len(payload)
                        self.buffer.append(fix_checksum(segment + payload, src_addr, dst_addr))
                        self.buffer_payload.append(len(payload))
                        i += 1
                    qtd_enviado = sum(self.pending_segments_payload)
                    for _ in range(len(self.buffer)):
                        if qtd_enviado + self.buffer_payload[0] > self.window_size:
                            break
                        payload = self.buffer.pop(0)
                        tam_payload = self.buffer_payload.pop(0)
                        self.servidor.rede.enviar(payload, dst_addr)
                        self._set_timer_info(payload, tam_payload)
                        qtd_enviado += tam_payload
                        
                    if self.timer is not None:
                        self.timer.cancel()
                    self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._exemplo_timer)
            else:
                self.servidor.rede.enviar(self.pending_segments[0], dst_addr)
        else:
            qtd_enviado = sum(self.pending_segments_payload)
            for j in range(len(self.buffer)):
                if qtd_enviado + self.buffer_payload[0] > self.window_size:
                    break
                payload = self.buffer.pop(0)
                tam_payload = self.buffer_payload.pop(0)
                self.servidor.rede.enviar(payload, dst_addr)
                self._set_timer_info(payload, tam_payload)
                qtd_enviado += tam_payload
                
            if self.timer is not None:
                self.timer.cancel()
            self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._exemplo_timer)
        
    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        src_addr, src_port, dst_addr, dst_port = self.id_conexao[0], self.id_conexao[1], \
             self.id_conexao[2], self.id_conexao[3] # Coleta informações de endereço

        flags = FLAGS_FIN
        segment = make_header(dst_port, src_port, self.seq_no + 1, self.ack_no, flags)
        self.servidor.rede.enviar(fix_checksum(segment, src_addr, dst_addr), dst_addr)
        pass