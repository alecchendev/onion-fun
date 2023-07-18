from secp256k1 import PrivateKey, PublicKey
import unittest
import hmac
from hashlib import sha256
from Crypto.Cipher import ChaCha20_Poly1305
import os


class OnionPacket:
    def __init__(self, ephemeral_pubkey: PublicKey, payloads: bytes, hmac: bytes):
        self.version = 0x00
        self.ephemeral_pubkey = ephemeral_pubkey
        self.payloads = payloads  # encrypted, includes next hops payloads
        self.hmac = hmac


class Payload:
    def __init__(
        self,
        next_node_id: PublicKey,
        encrypted_data: bytes | None,
        current_blinding_point: PublicKey | None,
    ):
        self.next_node_id = next_node_id  # blinded node id if inside blinded route
        self.encrypted_data = encrypted_data
        self.current_blinding_point = current_blinding_point

    # Simple serialization for now (usually is a TLV stream)
    def encode(self) -> bytes:
        w = bytes()
        w += self.next_node_id.serialize()
        if self.encrypted_data is not None:
            w += self.encrypted_data
        if self.current_blinding_point is not None:
            w += self.current_blinding_point.serialize()
        # encode length as well
        w = len(w).to_bytes(1) + w  # assume always 1 byte for length
        return w

    @staticmethod
    def decode(r: bytes) -> "Payload":
        # length decoded outside
        next_node_id = PublicKey(r[:33], raw=True)
        r = r[33:]
        encrypted_data = None
        current_blinding_point = None
        if len(r) > 0:
            encrypted_data = r[:33]  # encrypted bytes
            r = r[33:]
        if len(r) > 0:
            current_blinding_point = PublicKey(r[:33], raw=True)
        return Payload(next_node_id, encrypted_data, current_blinding_point)

    def encoded_length(self) -> int:
        return len(self.encode())


class EncryptedData:
    def __init__(
        self, next_node_id: PublicKey | None = None, secret: bytes | None = None
    ):
        assert not (next_node_id and secret)
        assert secret is None or len(secret) == 33

        self.next_node_id = next_node_id
        self.secret = secret

    def encode(self) -> bytes:
        w = bytes()
        if self.next_node_id is not None:
            w += self.next_node_id.serialize()
        if self.secret is not None:
            w += self.secret
        return w

    @staticmethod
    def decode(r: bytes) -> "EncryptedData":
        assert len(r) == 33
        next_node_id = None
        secret = None
        try:
            next_node_id = PublicKey(r[:33], raw=True)
        except:
            secret = r
        return EncryptedData(next_node_id, secret)


class OnionKeys:
    def __init__(self, shared_secret: bytes):
        self.rho = hmac.new(bytes([0x72, 0x68, 0x6F]), shared_secret, sha256).digest()
        self.mu = hmac.new(bytes([0x6D, 0x75]), shared_secret, sha256).digest()


# Implement basic route blinding
class Node:
    def __init__(self):
        self.privkey = PrivateKey()

    def node_id(self) -> PublicKey:
        return self.privkey.pubkey

    def create_blinded_route(
        self, hops: list["Node"]
    ) -> tuple[PublicKey, list[PublicKey], list[bytes], bytes]:
        hops.append(self)
        # Create blinded route for each hop to self
        blinded_node_ids = []
        encrypted_datas = []

        secret = os.urandom(33)
        ephemeral_key = PrivateKey()
        ephemeral_pubkey = ephemeral_key.pubkey
        first_ephemeral_pubkey = ephemeral_pubkey

        for i, hop in enumerate(hops):
            ss = hop.node_id().ecdh(ephemeral_key.private_key)
            blinded_node_id = hop.node_id().tweak_mul(
                hmac.new(b"blinded_node_id", ss, sha256).digest()
            )
            rho = hmac.new(b"rho", ss, sha256).digest()

            # Encrypt next hop or secret for final node (self) to verify route on receive
            data_to_encrypt = (
                EncryptedData(next_node_id=hops[i + 1].node_id())
                if i < len(hops) - 1
                else EncryptedData(secret=secret)
            )
            encrypted_data = ChaCha20_Poly1305.new(key=rho, nonce=bytes(12)).encrypt(
                data_to_encrypt.encode()
            )

            blinded_node_ids.append(blinded_node_id)
            encrypted_datas.append(encrypted_data)

            ephemeral_key = PrivateKey(
                ephemeral_key.tweak_mul(
                    sha256(ephemeral_pubkey.serialize() + ss).digest()
                )
            )
            ephemeral_pubkey = ephemeral_key.pubkey

        # skip the first blinded node id because it's the introduction node
        return (first_ephemeral_pubkey, blinded_node_ids[1:], encrypted_datas, secret)

    def route_to_blinded_route(
        self,
        hops: list["Node"],
        intoduction_node_id: PublicKey,
        first_blinding_ephemeral_pubkey: PublicKey,
        blinded_node_ids: list[PublicKey],
        encrypted_datas: list[bytes],
    ) -> OnionPacket:
        route = (
            [(hop.node_id(), 0) for hop in hops]
            + [(intoduction_node_id, 1)]
            + [(blinded_node_id, 2) for blinded_node_id in blinded_node_ids]
        )
        payloads = []
        blinded_node_ids.append(
            blinded_node_ids[-1]
        )  # add extra final node id to stub data for receive payload

        # Get payloads and keys
        for i, (node_id, hop_type) in enumerate(route):
            next_node_id = None
            encrypted_data = None
            current_blinding_point = None

            if hop_type == 0:
                next_node_id, _ = route[i + 1]  # assuming blinded route right now
            elif hop_type == 1:
                next_node_id = blinded_node_ids.pop(0)
                encrypted_data = encrypted_datas.pop(0)
                current_blinding_point = first_blinding_ephemeral_pubkey
            elif hop_type == 2:
                next_node_id = blinded_node_ids.pop(0)
                encrypted_data = encrypted_datas.pop(0)

            payloads.append(
                Payload(next_node_id, encrypted_data, current_blinding_point)
            )

        # Get keys
        onion_keys = []
        ephemeral_key = PrivateKey()
        ephemeral_pubkey = ephemeral_key.pubkey
        first_ephemeral_pubkey = ephemeral_pubkey
        for node_id, _ in route:
            ss = node_id.ecdh(ephemeral_key.private_key)
            new_keys = OnionKeys(ss)
            onion_keys.append(new_keys)
            ephemeral_key = PrivateKey(
                ephemeral_key.tweak_mul(
                    sha256(ephemeral_pubkey.serialize() + ss).digest()
                )
            )
            ephemeral_pubkey = ephemeral_key.pubkey

        packet_length = sum([payload.encoded_length() + 32 for payload in payloads])
        if packet_length <= 1300:
            packet_length = 1300
        elif packet_length <= 32768:
            packet_length = 32768
        else:
            raise Exception("Packet too large")

        # Generate filler
        filler = bytes()
        for payload, keys in zip(payloads[:-1], onion_keys[:-1]):
            cipher = ChaCha20_Poly1305.new(key=keys.rho, nonce=bytes(12))
            cipher.encrypt(bytes(packet_length - len(filler)))  # seek

            filler += bytes(payload.encoded_length() + 32)
            filler = cipher.encrypt(filler)

        # Encrypt and construct packet
        encrypted_payloads = bytes(packet_length)
        cipher = ChaCha20_Poly1305.new(key=os.urandom(32), nonce=bytes(12))
        encrypted_payloads = cipher.encrypt(encrypted_payloads)

        hmac_res = bytes(32)
        for i, (payload, keys) in reversed(list(enumerate(zip(payloads, onion_keys)))):
            # shift right, add payload + hmac
            shift_len = payload.encoded_length() + 32
            encrypted_payloads = (
                payload.encode() + hmac_res + encrypted_payloads[:-shift_len]
            )

            # encrypt
            cipher = ChaCha20_Poly1305.new(key=keys.rho, nonce=bytes(12))
            encrypted_payloads = cipher.encrypt(encrypted_payloads)

            # if recipient, replace end with filler
            if i == len(payloads) - 1:
                encrypted_payloads = encrypted_payloads[: -len(filler)] + filler

            # hmac
            hmac_res = hmac.new(keys.mu, encrypted_payloads, sha256).digest()

        return OnionPacket(first_ephemeral_pubkey, encrypted_payloads, hmac_res)

    def forward_onion(
        self, onion_packet: OnionPacket, blinding_point: PublicKey | None
    ) -> tuple[PublicKey, OnionPacket, PublicKey | None, bytes | None]:
        # decrypt onion, return next node id, onion, and next blinding point
        sphinx_privkey = self.privkey
        if blinding_point:
            blind_ss = blinding_point.ecdh(self.privkey.private_key)
            sphinx_privkey = PrivateKey(
                sphinx_privkey.tweak_mul(
                    hmac.new(b"blinded_node_id", blind_ss, sha256).digest()
                )
            )

        ephemeral_pubkey = onion_packet.ephemeral_pubkey
        sphinx_ss = ephemeral_pubkey.ecdh(sphinx_privkey.private_key)
        keys = OnionKeys(sphinx_ss)

        # Verify hmac
        hmac_res = hmac.new(keys.mu, onion_packet.payloads, sha256).digest()
        assert hmac_res == onion_packet.hmac  # will be unequal/zero for recipient

        # Decrypt payloads
        cipher = ChaCha20_Poly1305.new(key=keys.rho, nonce=bytes(12))
        decrypted_payloads = cipher.decrypt(onion_packet.payloads)

        # Decode values
        payload_length = int.from_bytes(decrypted_payloads[0:1])
        decrypted_payloads = decrypted_payloads[1:]  # pop length
        my_payload = Payload.decode(decrypted_payloads[:payload_length])
        next_hmac = decrypted_payloads[payload_length : payload_length + 32]
        decrypted_payloads = decrypted_payloads[
            payload_length + 32 :
        ]  # pop payload + hmac

        cipher = ChaCha20_Poly1305.new(key=keys.rho, nonce=bytes(12))
        cipher.encrypt(bytes(len(onion_packet.payloads)))  # seek
        decrypted_payloads += cipher.encrypt(
            bytes(my_payload.encoded_length() + 32)
        )  # add stream
        assert len(decrypted_payloads) == len(onion_packet.payloads)

        # Find next node (and blinding point)
        next_node_id = None
        next_blinding_point = None
        secret = None
        if my_payload.current_blinding_point or blinding_point:
            assert my_payload.encrypted_data is not None
            assert not (my_payload.current_blinding_point and blinding_point)

            this_blinding_point = my_payload.current_blinding_point or blinding_point
            # Decrypt encrypted data
            blind_ss = this_blinding_point.ecdh(self.privkey.private_key)
            rho = hmac.new(b"rho", blind_ss, sha256).digest()
            decrypted_data = ChaCha20_Poly1305.new(key=rho, nonce=bytes(12)).decrypt(
                my_payload.encrypted_data
            )
            data = EncryptedData.decode(decrypted_data)
            next_node_id = data.next_node_id
            secret = data.secret
            next_blinding_point = this_blinding_point.tweak_mul(
                sha256(this_blinding_point.serialize() + blind_ss).digest()
            )

        else:
            assert my_payload.encrypted_data is None
            next_node_id = my_payload.next_node_id

        # Construct next onion
        next_ephemeral_pubkey = ephemeral_pubkey.tweak_mul(
            sha256(ephemeral_pubkey.serialize() + sphinx_ss).digest()
        )
        next_onion_packet = OnionPacket(
            next_ephemeral_pubkey, decrypted_payloads, next_hmac
        )

        return next_node_id, next_onion_packet, next_blinding_point, secret


class TestOnion(unittest.TestCase):
    def test_onion(self):
        # Setup 5 nodes
        nodes = [Node() for _ in range(5)]

        # Create a blinded route from nodes 2-4
        blind_hops = [nodes[2], nodes[3]]
        introduction_node = blind_hops[0]
        (
            first_ephemeral_key,
            blinded_node_ids,
            encrypted_datas,
            initial_secret,
        ) = nodes[4].create_blinded_route(blind_hops)
        assert len(blinded_node_ids) == 2  # should be recipient and prev

        # Give the blinded route to node 0
        # Node 0 finds a route to node 2
        clear_hops = [nodes[1]]
        onion_packet = nodes[0].route_to_blinded_route(
            clear_hops,
            introduction_node.node_id(),
            first_ephemeral_key,
            blinded_node_ids,
            encrypted_datas,
        )

        # Forward through node 2
        next_node_id, onion_packet, blinding_point, secret = nodes[1].forward_onion(
            onion_packet, None
        )
        assert next_node_id.serialize() == nodes[2].node_id().serialize()
        assert blinding_point is None
        assert secret is None

        # Forward through node 2
        next_node_id, onion_packet, blinding_point, secret = nodes[2].forward_onion(
            onion_packet, blinding_point
        )
        assert next_node_id.serialize() == nodes[3].node_id().serialize()
        assert blinding_point is not None
        assert secret is None

        # Forward through node 3
        next_node_id, onion_packet, blinding_point, secret = nodes[3].forward_onion(
            onion_packet, blinding_point
        )
        assert next_node_id.serialize() == nodes[4].node_id().serialize()
        assert blinding_point is not None
        assert secret is None

        # Receive as node 4
        next_node_id, onion_packet, blinding_point, secret = nodes[4].forward_onion(
            onion_packet, blinding_point
        )
        assert next_node_id is None
        assert secret == initial_secret
