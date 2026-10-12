#!/usr/bin/env python3
"""KrotP v1 authenticated DNS-to-TCP server. Python 3.11+."""
import argparse
import asyncio
import base64
import ipaddress
import logging
import os
import secrets
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from dnslib import DNSRecord, RR, TXT, A, RD, EDNS0, QTYPE

OPEN, DATA, CLOSE, POLL, PING, PONG, ACK, ERROR, FIN, OPEN_PART = range(1, 11)
HEADER = struct.Struct('!BIQQH')
WINDOW = 64


def hkdf(key, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(key)


def master_key(password, domain):
    return hkdf(password.encode(), b'krot-v1', domain.encode())


def direction_key(master, session, direction):
    return hkdf(hkdf(master, session, b''), b'krot-v1', direction)


def frame(kind, stream=0, seq=0, ack=0, data=b''):
    return HEADER.pack(kind, stream, seq, ack, len(data)) + data


def unframe(raw):
    if len(raw) < HEADER.size:
        raise ValueError('short frame')
    kind, stream, seq, ack, length = HEADER.unpack_from(raw)
    if kind not in range(1, 11) or len(raw) != HEADER.size + length:
        raise ValueError('invalid frame')
    return kind, stream, seq, ack, raw[HEADER.size:]


def b32(raw):
    return base64.b32encode(raw).decode().rstrip('=').lower()


def unb32(s):
    return base64.b32decode(s.upper() + '=' * (-len(s) % 8))


def query_name(ciphertext, session, nonce, domain):
    encoded = b32(ciphertext)
    labels = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    name = '.'.join(labels + [b32(session + nonce), domain])
    if len(name.encode()) + 2 > 255:
        raise ValueError('QNAME exceeds 255 wire bytes')
    return name


@dataclass
class Stream:
    host: str
    port: int
    chunk: int
    opening: asyncio.Task | None = None
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    read_task: asyncio.Task | None = None
    incoming: dict = field(default_factory=dict)
    outgoing: dict = field(default_factory=dict)
    up_next: int = 0
    down_next: int = 0
    down_ack: int = 0
    eof: bool = False
    closed: bool = False
    error: bool = False
    fin: int | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    changed: asyncio.Event = field(default_factory=asyncio.Event)

    async def connect(self, allow_private):
        try:
            # Resolve once and connect to the checked numeric IP (no DNS rebinding).
            infos = await asyncio.get_running_loop().getaddrinfo(self.host, self.port, type=1)
            addresses = [i[4][0] for i in infos if allow_private or ipaddress.ip_address(i[4][0]).is_global]
            if not addresses:
                raise ValueError('destination denied')
            for address in addresses:
                try:
                    self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(address, self.port), 8)
                    break
                except (OSError, asyncio.TimeoutError):
                    continue
            if not self.writer:
                raise OSError('connect failed')
            if self.closed:
                self.writer.close()
                return
            self.read_task = asyncio.create_task(self.read_remote())
        except Exception:
            self.error = True
            self.eof = True

    async def read_remote(self):
        try:
            while not self.closed:
                while len(self.outgoing) >= WINDOW and not self.closed:
                    self.changed.clear()
                    await self.changed.wait()
                if self.closed:
                    break
                data = await self.reader.read(self.chunk)
                if not data:
                    break
                self.outgoing[self.down_next] = data
                self.down_next += 1
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            self.eof = True

    def shutdown(self):
        self.closed = True
        self.incoming.clear()
        self.outgoing.clear()
        self.changed.set()
        if self.read_task:
            self.read_task.cancel()
        if self.opening and not self.opening.done():
            self.opening.cancel()
        if self.writer:
            self.writer.close()


@dataclass
class Session:
    up: bytes
    down: bytes
    qtype: int
    prefix: bytes = field(default_factory=lambda: secrets.token_bytes(4))
    counter: int = 0
    streams: dict = field(default_factory=dict)
    staged: dict = field(default_factory=dict)
    seen: OrderedDict = field(default_factory=OrderedDict)
    touched: float = field(default_factory=time.monotonic)

    def seal(self, plain):
        self.counter += 1
        nonce = self.prefix + struct.pack('!Q', self.counter)
        return nonce + ChaCha20Poly1305(self.down).encrypt(nonce, plain, b'krot-v1-down')

    def shutdown(self):
        for stream in self.streams.values():
            stream.shutdown()


class KrotServer(asyncio.DatagramProtocol):
    def __init__(self, domain, password, max_response=900, allow_private=False,
                 max_sessions=128, max_streams=64, idle_timeout=120):
        self.domain = domain.lower().strip('.')
        self.master = master_key(password, self.domain)
        self.max_response = max_response
        self.allow_private = allow_private
        self.max_sessions = max_sessions
        self.max_streams = max_streams
        self.idle_timeout = idle_timeout
        self.sessions = {}
        self.tasks = set()
        self.transport = None
        self.janitor = None

    def connection_made(self, transport):
        self.transport = transport
        self.janitor = asyncio.create_task(self.reap())

    def connection_lost(self, exc):
        if self.janitor:
            self.janitor.cancel()
        for task in self.tasks:
            task.cancel()
        for session in self.sessions.values():
            session.shutdown()

    def datagram_received(self, data, addr):
        if len(data) > 1232 or len(self.tasks) >= 512:
            return
        task = asyncio.create_task(self.handle(data, addr))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def reap(self):
        while True:
            await asyncio.sleep(15)
            now = time.monotonic()
            for sid, session in list(self.sessions.items()):
                if now - session.touched > self.idle_timeout:
                    session.shutdown()
                    del self.sessions[sid]

    def response(self, request, packet):
        reply = request.reply(ra=0, aa=1)
        qtype = request.q.qtype
        name = request.q.qname
        if qtype == QTYPE.TXT:
            encoded = base64.urlsafe_b64encode(packet).rstrip(b'=')
            reply.add_answer(RR(name, QTYPE.TXT, ttl=0,
                                rdata=TXT([encoded[i:i+255] for i in range(0, len(encoded), 255)])))
        elif qtype == QTYPE.NULL:
            reply.add_answer(RR(name, QTYPE.NULL, ttl=0, rdata=RD(packet)))
        elif qtype == QTYPE.A:
            # Length prefix + indexed fragments; RR order is not significant.
            raw = struct.pack('!H', len(packet)) + packet
            for index, offset in enumerate(range(0, len(raw), 3)):
                part = raw[offset:offset+3].ljust(3, b'\0')
                reply.add_answer(RR(name, QTYPE.A, ttl=0, rdata=A(tuple(bytes([index]) + part))))
        reply.add_ar(EDNS0(udp_len=1232))
        return reply.pack()

    def chunk_size(self, request, requested):
        # POLL has fixed, shorter QNAME. Conservatively retain the OPEN question
        # so every data reply fits even with a long destination hostname.
        size = min(requested, self.max_response, 700 if request.q.qtype == QTYPE.A else 1100)
        while size >= 100:
            dummy = bytes(12 + 16 + HEADER.size + size)
            if len(self.response(request, dummy)) <= 1232:
                return size
            size -= 1
        raise ValueError('response budget too small')

    async def handle(self, raw, addr):
        try:
            request = DNSRecord.parse(raw)
            if request.header.qr or request.header.opcode or len(request.questions) != 1:
                return
            if request.q.qtype not in (QTYPE.TXT, QTYPE.NULL, QTYPE.A) or request.q.qclass != 1:
                return
            opt = [r for r in request.ar if r.rtype == QTYPE.OPT]
            if not opt or opt[0].rclass < 1232:
                return
            labels = str(request.q.qname).rstrip('.').lower().split('.')
            suffix = self.domain.split('.')
            if labels[-len(suffix):] != suffix:
                return
            labels = labels[:-len(suffix)]
            if len(labels) < 2 or any(not x or len(x) > 63 for x in labels):
                return
            meta = unb32(labels[-1])
            if len(meta) != 20:
                return
            sid, nonce = meta[:8], meta[8:]
            cipher = unb32(''.join(labels[:-1]))
            up = direction_key(self.master, sid, b'up')
            plain = ChaCha20Poly1305(up).decrypt(nonce, cipher, b'krot-v1-up')
            parsed = unframe(plain)
            session = self.sessions.get(sid)
            if session is None:
                if len(self.sessions) >= self.max_sessions or parsed[0] != PING:
                    return
                session = Session(up, direction_key(self.master, sid, b'down'), request.q.qtype)
                self.sessions[sid] = session
            if session.qtype != request.q.qtype:
                return
            session.touched = time.monotonic()
            # Exact replay never performs side effects twice. Each retransmission
            # normally uses a fresh nonce; sequence IDs handle those duplicates.
            if nonce in session.seen:
                cached = session.seen[nonce]
                if cached is not None:
                    self.transport.sendto(self.response(request, cached), addr)
                return
            session.seen[nonce] = None
            result = await self.dispatch(session, request, *parsed)
            packet = session.seal(result)
            session.seen[nonce] = packet
            while len(session.seen) > 4096:
                session.seen.popitem(last=False)
            response = self.response(request, packet)
            if len(response) <= 1232:
                self.transport.sendto(response, addr)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Malformed names, bad MACs, foreign replies: silent by design.
            return

    async def dispatch(self, session, request, kind, sid, seq, ack, payload):
        if kind == PING and sid == 0 and not payload:
            return frame(PONG)
        if sid == 0:
            return frame(ERROR, sid)
        stream = session.streams.get(sid)
        if kind == OPEN_PART:
            if stream is not None:
                return frame(ACK, sid, seq)
            if not (1 <= ack <= 4 and seq < ack and 1 <= len(payload) <= 180):
                return frame(ERROR, sid)
            if sid not in session.staged and len(session.staged) >= self.max_streams:
                return frame(ERROR, sid)
            total, parts = session.staged.setdefault(sid, (ack, {}))
            if total != ack or (seq in parts and parts[seq] != payload):
                return frame(ERROR, sid)
            parts[seq] = payload
            return frame(ACK, sid, seq)
        if kind == OPEN:
            if not payload:
                if stream is not None:
                    host_bytes = stream.host.encode('ascii')
                    payload = bytes([len(host_bytes)]) + host_bytes + struct.pack('!HH', stream.port, stream.chunk)
                else:
                    total, parts = session.staged.get(sid, (0, {}))
                    if not total or len(parts) != total:
                        return frame(ERROR, sid)
                    payload = b''.join(parts[i] for i in range(total))
            if len(payload) < 5:
                return frame(ERROR, sid)
            n = payload[0]
            if len(payload) != n + 5 or not n:
                return frame(ERROR, sid)
            host = payload[1:1+n].decode('ascii')
            port, requested = struct.unpack('!HH', payload[1+n:])
            if not port or not 100 <= requested <= 1100:
                return frame(ERROR, sid)
            if stream is None:
                if sum(not s.closed for s in session.streams.values()) >= self.max_streams or len(session.streams) >= 4096:
                    return frame(ERROR, sid)
                stream = Stream(host, port, self.chunk_size(request, requested))
                session.streams[sid] = stream
                session.staged.pop(sid, None)
                stream.opening = asyncio.create_task(stream.connect(self.allow_private))
            if stream.host != host or stream.port != port or stream.closed:
                return frame(ERROR, sid)
            await asyncio.shield(stream.opening)
            return frame(ERROR if stream.error else ACK, sid, data=struct.pack('!H', stream.chunk))
        if stream is None:
            return frame(ERROR, sid)
        async with stream.lock:
            if ack > stream.down_next:
                return frame(ERROR, sid)
            if ack > stream.down_ack:
                for key in list(stream.outgoing):
                    if key < ack:
                        del stream.outgoing[key]
                stream.down_ack = ack
                stream.changed.set()
            if kind == CLOSE:
                stream.shutdown()
                return frame(ACK, sid, seq)
            if stream.closed or stream.error:
                return frame(ERROR, sid)
            if kind == DATA:
                if not payload or seq >= stream.up_next + WINDOW or (stream.fin is not None and seq >= stream.fin):
                    return frame(ERROR, sid)
                if seq >= stream.up_next:
                    old = stream.incoming.get(seq)
                    if old is not None and old != payload:
                        return frame(ERROR, sid)
                    stream.incoming[seq] = payload
                    while stream.up_next in stream.incoming:
                        stream.writer.write(stream.incoming.pop(stream.up_next))
                        # Once queued to TCP, this block must never be written twice,
                        # including when drain times out after a partial delivery.
                        stream.up_next += 1
                        try:
                            await asyncio.wait_for(stream.writer.drain(), 10)
                        except (OSError, asyncio.TimeoutError):
                            stream.error = True
                            stream.shutdown()
                            return frame(ERROR, sid)
                if stream.fin == stream.up_next and stream.writer.can_write_eof():
                    stream.writer.write_eof()
                return frame(ACK, sid, seq)
            if kind == FIN:
                if seq < stream.up_next or seq >= stream.up_next + WINDOW or (stream.fin is not None and stream.fin != seq):
                    return frame(ERROR, sid)
                stream.fin = seq
                if seq == stream.up_next and stream.writer.can_write_eof():
                    stream.writer.write_eof()
                return frame(ACK, sid, seq)
            if kind == POLL and not payload:
                if seq < stream.down_ack or seq >= stream.down_ack + WINDOW:
                    return frame(PONG, sid, seq)
                data = stream.outgoing.get(seq)
                if data is not None:
                    return frame(DATA, sid, seq, data=data)
                if stream.eof:
                    return frame(CLOSE, sid, stream.down_next)
                return frame(PONG, sid, seq)
            return frame(ERROR, sid)


async def main(args):
    password = os.environ.get('KROT_PASSWORD', '')
    if len(password) < 16:
        raise SystemExit('Set KROT_PASSWORD to a random secret of at least 16 characters')
    if not 100 <= args.max_response <= 1100:
        raise SystemExit('--max-response must be 100..1100')
    domain = args.domain.lower().strip('.')
    if not domain.startswith('tunnel.') or any(not label or len(label) > 63 for label in domain.split('.')):
        raise SystemExit('--domain must be a valid delegated tunnel.example.ru zone')
    if len(domain) > 90:
        raise SystemExit('Use a shorter domain (at most 90 characters)')
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: KrotServer(domain, password, args.max_response, args.allow_private),
        local_addr=(args.bind, args.port))
    logging.info('Krot listening on %s:%d, zone %s', args.bind, args.port, domain)
    try:
        await asyncio.Future()
    finally:
        transport.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True, help='Delegated zone, e.g. tunnel.example.ru')
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--max-response', type=int, default=900)
    parser.add_argument('--allow-private', action='store_true', help='Permit LAN/loopback destinations')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    asyncio.run(main(parser.parse_args()))
