import asyncio
import base64
import os
import random
import secrets
import struct
import unittest

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from dnslib import DNSRecord, EDNS0, QTYPE
from krot import *

DOMAIN = 'tunnel.example.ru'
PASSWORD = 'test-password-only-32-characters!'

class Client(asyncio.DatagramProtocol):
    def __init__(self, endpoint, qtype=16, loss=False):
        self.endpoint = endpoint
        self.sid = secrets.token_bytes(8)
        self.master = master_key(PASSWORD, DOMAIN)
        self.up = direction_key(self.master, self.sid, b'up')
        self.down = direction_key(self.master, self.sid, b'down')
        self.prefix = secrets.token_bytes(4)
        self.counter = 0
        self.pending = {}
        self.qtype = qtype
        self.loss = loss
        self.received = 0
        self.max_flight = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr != self.endpoint:
            return
        self.received += 1
        # Deterministic drops exercise retries rather than a flaky random test.
        if self.loss and self.received % 5 == 0:
            return
        try:
            reply = DNSRecord.parse(data)
            future, name = self.pending[reply.header.id]
            assert str(reply.q.qname).rstrip('.').lower() == name
            assert len(data) <= 1232 and not reply.header.tc
            assert all(r.ttl == 0 for r in reply.rr)
            if self.qtype == 16:
                text = b''.join(reply.rr[0].rdata.data)
                packet = base64.urlsafe_b64decode(text + b'=' * (-len(text) % 4))
            elif self.qtype == 10:
                packet = reply.rr[0].rdata.data
            else:
                fragments = sorted(bytes(r.rdata.data) for r in reversed(reply.rr))
                joined = b''.join(r[1:] for r in fragments)
                length = struct.unpack('!H', joined[:2])[0]
                packet = joined[2:2+length]
            nonce = packet[:12]
            plain = ChaCha20Poly1305(self.down).decrypt(nonce, packet[12:], b'krot-v1-down')
            if not future.done():
                future.set_result(unframe(plain))
        except Exception:
            pass

    def encode(self, plain):
        self.counter += 1
        nonce = self.prefix + struct.pack('!Q', self.counter)
        cipher = ChaCha20Poly1305(self.up).encrypt(nonce, plain, b'krot-v1-up')
        name = query_name(cipher, self.sid, nonce, DOMAIN)
        query = DNSRecord.question(name, QTYPE[self.qtype])
        while query.header.id in self.pending:
            query.header.id = secrets.randbelow(65536)
        query.add_ar(EDNS0(udp_len=1232))
        return query, name

    async def rpc(self, plain):
        for _ in range(8):
            query, name = self.encode(plain)
            future = asyncio.get_running_loop().create_future()
            self.pending[query.header.id] = (future, name)
            self.max_flight = max(self.max_flight, len(self.pending))
            self.transport.sendto(query.pack(), self.endpoint)
            try:
                return await asyncio.wait_for(future, 0.2 + (POLL_HOLD if plain[0] == POLL else 0))
            except asyncio.TimeoutError:
                pass
            finally:
                del self.pending[query.header.id]
        raise TimeoutError('DNS exchange')


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def echo(reader, writer):
            try:
                while data := await reader.read(2048):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        self.echo = await asyncio.start_server(echo, '127.0.0.1', 0)
        self.echo_port = self.echo.sockets[0].getsockname()[1]
        self.server = KrotServer(DOMAIN, PASSWORD, allow_private=True)
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(lambda: self.server, local_addr=('127.0.0.1', 0))
        self.endpoint = self.transport.get_extra_info('sockname')
        self.clients = []

    async def asyncTearDown(self):
        for client in self.clients:
            client.transport.close()
        self.transport.close()
        self.echo.close()
        await self.echo.wait_closed()
        await asyncio.sleep(0.02)

    async def client(self, qtype=16, loss=False):
        client = Client(self.endpoint, qtype, loss)
        await asyncio.get_running_loop().create_datagram_endpoint(lambda: client, local_addr=('127.0.0.1', 0))
        self.clients.append(client)
        self.assertEqual((await client.rpc(frame(PING)))[0], PONG)
        return client

    async def transfer(self, qtype, loss=False):
        client = await self.client(qtype, loss)
        payload = bytes([9]) + b'127.0.0.1' + struct.pack('!HH', self.echo_port, 1100)
        opened = await client.rpc(frame(OPEN, 1, data=payload))
        self.assertEqual(opened[0], ACK)
        chunk = struct.unpack('!H', opened[4])[0]
        self.assertTrue(100 <= chunk <= 1100)
        data = os.urandom(8192)
        blocks = [data[i:i+80] for i in range(0, len(data), 80)]
        # Bounded waves: shuffled arrival plus fresh-nonce duplicates.
        for offset in range(0, len(blocks), 16):
            indexes = list(range(offset, min(offset+16, len(blocks))))
            random.Random(offset).shuffle(indexes)
            replies = await asyncio.gather(*(client.rpc(frame(DATA, 1, i, data=blocks[i])) for i in indexes))
            self.assertTrue(all(r[0] == ACK for r in replies))
            self.assertEqual((await client.rpc(frame(DATA, 1, indexes[0], data=blocks[indexes[0]])))[0], ACK)
        await client.rpc(frame(FIN, 1, len(blocks)))
        received = bytearray(); seq = 0
        for _ in range(256):
            reply = await client.rpc(frame(POLL, 1, seq, seq))
            if reply[0] == DATA:
                # Lost downstream ACK must yield identical data on a fresh poll.
                duplicate = await client.rpc(frame(POLL, 1, seq, seq))
                self.assertEqual(duplicate[4], reply[4])
                received.extend(reply[4]); seq += 1
            elif reply[0] == CLOSE:
                self.assertEqual(reply[2], seq)
                break
            else:
                await asyncio.sleep(.01)
        else:
            self.fail('no EOF')
        self.assertEqual(bytes(received), data)
        self.assertGreaterEqual(client.max_flight, 8)
        await client.rpc(frame(CLOSE, 1, ack=seq))

    async def test_txt_loss_reorder_duplicates(self):
        await self.transfer(QTYPE.TXT, True)

    async def test_null(self):
        await self.transfer(QTYPE.NULL)

    async def test_a_reordered_records(self):
        await self.transfer(QTYPE.A)

    async def test_silence_and_auth(self):
        client = await self.client()
        before = client.received
        for raw in (b'garbage', DNSRecord.question('example.org').pack()):
            client.transport.sendto(raw, self.endpoint)
        query, _ = client.encode(frame(PING))
        query.ar.clear() # EDNS is mandatory
        client.transport.sendto(query.pack(), self.endpoint)
        query, _ = client.encode(frame(PING))
        query.ar.clear(); query.add_ar(EDNS0(udp_len=512))
        client.transport.sendto(query.pack(), self.endpoint)
        query, _ = client.encode(frame(PING))
        wire = bytearray(query.pack()); wire[14] ^= 1 # corrupt ciphertext label
        client.transport.sendto(wire, self.endpoint)
        await asyncio.sleep(.1)
        self.assertEqual(client.received, before)
        # Only our zone is counted, so the periodic log shows the resolver chain's EDNS.
        self.assertEqual((self.server.edns_drops, self.server.edns_min), (2, 512))
        self.assertEqual((await client.rpc(frame(PING)))[0], PONG)

    async def test_tcp_drain_failure_never_duplicates_write(self):
        class Writer:
            def __init__(self): self.writes = []
            def write(self, data): self.writes.append(data)
            async def drain(self): raise asyncio.TimeoutError()
            def close(self): pass
        session = Session(b'x' * 32, b'y' * 32, QTYPE.TXT)
        writer = Writer()
        stream = Stream('127.0.0.1', 80, 600, writer=writer)
        session.streams[1] = stream
        for _ in range(2):
            result = await self.server.dispatch(session, None, DATA, 1, 0, 0, b'once')
            self.assertEqual(unframe(result)[0], ERROR)
        self.assertEqual(writer.writes, [b'once'])
        self.assertTrue(stream.closed)

    def stream(self, chunk=600):
        session = Session(b'x' * 32, b'y' * 32, QTYPE.TXT)
        stream = Stream('127.0.0.1', 80, chunk)
        session.streams[1] = stream
        return session, stream

    async def test_blocks_are_full_and_cut_on_demand(self):
        self.server.poll_hold = 0.05
        session, stream = self.stream()
        stream.buffer.extend(os.urandom(1900))
        poll = lambda seq: self.server.dispatch(session, None, POLL, 1, seq, 0, b'')
        # Lanes ahead of the head get full blocks; small TCP reads never leak through.
        reply = unframe(await poll(2))
        self.assertEqual((reply[0], reply[2], len(reply[4])), (DATA, 2, 600))
        self.assertEqual([len(stream.outgoing[i]) for i in range(3)], [600, 600, 600])
        # A lane ahead of the head does not cut the 100-byte tail...
        self.assertEqual(unframe(await poll(4))[0], PONG)
        self.assertEqual(stream.down_next, 3)
        # ...the head lane does, so trickling data is still delivered at once.
        self.assertEqual(len(unframe(await poll(3))[4]), 100)

    async def test_long_poll_returns_data_as_it_arrives(self):
        session, stream = self.stream()
        poll = lambda: self.server.dispatch(session, None, POLL, 1, 0, 0, b'')
        loop = asyncio.get_running_loop()
        self.server.poll_hold = 0.1
        started = loop.time()
        self.assertEqual(unframe(await poll())[0], PONG)
        self.assertGreaterEqual(loop.time() - started, 0.09)
        self.server.poll_hold = 2
        def arrive():
            stream.buffer.extend(b'late')
            stream.readable.set()
        loop.call_later(0.05, arrive)
        started = loop.time()
        reply = unframe(await poll())
        self.assertEqual((reply[0], reply[4]), (DATA, b'late'))
        self.assertLess(loop.time() - started, 1)
        stream.eof = True
        stream.readable.set()
        self.assertEqual(unframe(await self.server.dispatch(session, None, POLL, 1, 1, 1, b''))[:3], (CLOSE, 1, 1))

    async def test_fragmented_open_idempotent(self):
        client = await self.client()
        payload = bytes([9]) + b'127.0.0.1' + struct.pack('!HH', self.echo_port, 900)
        parts = [payload[:5], payload[5:]]
        for index in (1, 0, 0):
            self.assertEqual((await client.rpc(frame(OPEN_PART, 3, index, 2, parts[index])))[0], ACK)
        self.assertEqual((await client.rpc(frame(OPEN, 3)))[0], ACK)
        writer = self.server.sessions[client.sid].streams[3].writer
        self.assertEqual((await client.rpc(frame(OPEN, 3)))[0], ACK)
        self.assertIs(self.server.sessions[client.sid].streams[3].writer, writer)
        await client.rpc(frame(CLOSE, 3))
        self.assertEqual((await client.rpc(frame(OPEN, 3)))[0], ERROR)

    async def test_failed_open_and_limits(self):
        client = await self.client()
        payload = bytes([9]) + b'127.0.0.1' + struct.pack('!HH', self.echo_port, 900)
        self.server.allow_private = False
        self.assertEqual((await client.rpc(frame(OPEN, 1, data=payload)))[0], ERROR)
        self.assertEqual((await client.rpc(frame(POLL, 999)))[0], ERROR)

    async def test_future_ack_and_window(self):
        client = await self.client()
        payload = bytes([9]) + b'127.0.0.1' + struct.pack('!HH', self.echo_port, 900)
        await client.rpc(frame(OPEN, 1, data=payload))
        self.assertEqual((await client.rpc(frame(DATA, 1, 64, data=b'x')))[0], ERROR)
        self.assertEqual((await client.rpc(frame(POLL, 1, ack=1)))[0], ERROR)

class ProtocolTests(unittest.TestCase):
    def test_vectors(self):
        key = master_key(PASSWORD, DOMAIN)
        sid = bytes(range(8)); nonce = bytes(range(12)); plain = frame(DATA, 7, 9, 3, b'hello')
        up = direction_key(key, sid, b'up'); down = direction_key(key, sid, b'down')
        self.assertNotEqual(up, down)
        cipher = ChaCha20Poly1305(up).encrypt(nonce, plain, b'krot-v1-up')
        self.assertEqual(ChaCha20Poly1305(up).decrypt(nonce, cipher, b'krot-v1-up'), plain)
        for size in range(1, 120):
            try:
                name = query_name(cipher + bytes(size), sid, nonce, DOMAIN)
            except ValueError:
                break
            self.assertLessEqual(len(name) + 2, 255)
            self.assertEqual(unb32(b32(cipher).upper()), cipher)
        with self.assertRaises(ValueError):
            unframe(b'broken')
        with self.assertRaises(ValueError):
            unframe(plain + b'x')

if __name__ == '__main__':
    unittest.main()
