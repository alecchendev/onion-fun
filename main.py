from secp256k1 import PrivateKey, PublicKey
import unittest
import hmac
from hashlib import sha256
from Crypto.Cipher import ChaCha20_Poly1305
import os


class OnionPacket:
    def __init__(self, ephemeral_pubkey: PublicKey, payloads: bytes, hmac: bytes):
        assert len(payloads) == 1300
        assert len(hmac) == 32

        self.version = 0x00
        self.ephemeral_pubkey = ephemeral_pubkey
        self.payloads = payloads  # encrypted, includes next hops payloads
        self.hmac = hmac


class Payload:
    def __init__(
        self,
        next_node_id: PublicKey,
        encrypted_data: bytes | None = None,
        current_blinding_point: PublicKey | None = None,
    ):
        self.next_node_id = next_node_id  # blinded node id if inside blinded route
        self.encrypted_data = encrypted_data
        self.current_blinding_point = current_blinding_point

    def encode(self) -> bytes:
        w = bytes()
        w += self.next_node_id.serialize()
        if self.encrypted_data is not None:
            w += self.encrypted_data
        if self.current_blinding_point is not None:
            w += self.current_blinding_point.serialize()
        # encode length as 1 byte
        w = len(w).to_bytes(1) + w
        return w

    @staticmethod
    def decode(r: bytes) -> "Payload":
        # length decoded outside
        next_node_id = PublicKey(r[:33], raw=True)
        r = r[33:]

        encrypted_data = None
        if len(r) > 0:
            length = EncryptedData.encoded_length()
            encrypted_data = r[:length]
            r = r[length:]

        current_blinding_point = None
        if len(r) > 0:
            current_blinding_point = PublicKey(r[:33], raw=True)
            r = r[33:]

        assert len(r) == 0
        return Payload(next_node_id, encrypted_data, current_blinding_point)

    def encoded_length(self) -> int:
        return len(self.encode())


class EncryptedData:
    def __init__(
        self, next_node_id: PublicKey | None = None, secret: bytes | None = None
    ):
        assert next_node_id or secret
        assert not (next_node_id and secret)
        assert secret is None or len(secret) == 33

        self.next_node_id = next_node_id
        self.secret = secret

    def encode(self) -> bytes:
        """Write 1 byte to indicate which field is present, then the field itself (33 bytes)"""
        w = bytes()
        if self.next_node_id:
            w += bytes([0])
            w += self.next_node_id.serialize()
        elif self.secret:
            w += bytes([1])
            w += self.secret
        assert len(w) == 1 + 33
        return w

    @staticmethod
    def decode(r: bytes) -> "EncryptedData":
        assert len(r) == 1 + 33
        is_secret = r[0] == 1
        r = r[1:]
        if is_secret:
            secret = r[:33]
            return EncryptedData(secret=secret)
        else:
            next_node_id = PublicKey(r[:33], raw=True)
            return EncryptedData(next_node_id)

    @staticmethod
    def encoded_length() -> int:
        return 34


class OnionKeys:
    def __init__(self, shared_secret: bytes):
        assert len(shared_secret) == 32
        self.rho = hmac.new(bytes([0x72, 0x68, 0x6F]), shared_secret, sha256).digest()
        self.mu = hmac.new(bytes([0x6D, 0x75]), shared_secret, sha256).digest()


def create_payloads(
    hops: list["Node"],
    introduction_node_id: PublicKey,
    first_blinding_ephemeral_pubkey: PublicKey,
    blinded_node_ids: list[PublicKey],
    encrypted_datas: list[bytes],
) -> list[Payload]:
    # Form payloads
    payloads = []

    # Clear hops
    for i, hop in enumerate(hops):
        next_node_id = introduction_node_id
        if i < len(hops) - 1:
            next_node_id = hops[i + 1].node_id()
        payloads.append(Payload(next_node_id))

    # Introduction node
    payloads.append(
        Payload(
            next_node_id=blinded_node_ids[0],
            encrypted_data=encrypted_datas[0],
            current_blinding_point=first_blinding_ephemeral_pubkey,
        )
    )

    # Push an extra stub node id for the recipient's "next node"
    blinded_node_ids.append(blinded_node_ids[-1])
    assert len(encrypted_datas) == len(blinded_node_ids)

    # Blinded hops
    for blinded_node_id, encrypted_data in zip(
        blinded_node_ids[1:], encrypted_datas[1:]
    ):
        payloads.append(
            Payload(
                next_node_id=blinded_node_id,
                encrypted_data=encrypted_data,
            )
        )

    return payloads


def create_onion_keys(route: list[PublicKey]) -> tuple[list[OnionKeys], PublicKey]:
    onion_keys = []
    ephemeral_key = PrivateKey()
    ephemeral_pubkey = ephemeral_key.pubkey
    first_ephemeral_pubkey = ephemeral_pubkey
    for node_id in route:
        ss = node_id.ecdh(ephemeral_key.private_key)
        new_keys = OnionKeys(ss)
        onion_keys.append(new_keys)

        ephemeral_key = PrivateKey(
            ephemeral_key.tweak_mul(sha256(ephemeral_pubkey.serialize() + ss).digest())
        )
        ephemeral_pubkey = ephemeral_key.pubkey

    return onion_keys, first_ephemeral_pubkey


def create_filler(
    packet_length: int, payloads: list[Payload], onion_keys: list[OnionKeys]
) -> bytes:
    assert len(payloads) == len(onion_keys)
    filler = bytes()
    for payload, keys in zip(payloads[:-1], onion_keys[:-1]):
        cipher = ChaCha20_Poly1305.new(key=keys.rho, nonce=bytes(12))
        cipher.encrypt(bytes(packet_length - len(filler)))  # seek

        filler += bytes(payload.encoded_length() + 32)
        filler = cipher.encrypt(filler)
    return filler


def create_onion_payloads(
    packet_length: int,
    payloads: list[Payload],
    onion_keys: list[OnionKeys],
    filler: bytes,
) -> tuple[bytes, bytes]:
    assert len(payloads) == len(onion_keys)

    # Initialize as prng stream
    encrypted_payloads = bytes(packet_length)
    cipher = ChaCha20_Poly1305.new(key=os.urandom(32), nonce=bytes(12))
    encrypted_payloads = cipher.encrypt(encrypted_payloads)

    # Add the layers (payloads) of the onion
    hmac_res = bytes(32)
    for i, (payload, keys) in reversed(list(enumerate(zip(payloads, onion_keys)))):
        # shift right, add payload + hmac
        shift_len = payload.encoded_length() + 32
        encrypted_payloads = (
            payload.encode() + hmac_res + encrypted_payloads[:-shift_len]
        )

        # Encrypt
        cipher = ChaCha20_Poly1305.new(key=keys.rho, nonce=bytes(12))
        encrypted_payloads = cipher.encrypt(encrypted_payloads)

        # If recipient, replace end with filler
        if i == len(payloads) - 1:
            encrypted_payloads = encrypted_payloads[: -len(filler)] + filler

        # Compute hmac
        hmac_res = hmac.new(keys.mu, encrypted_payloads, sha256).digest()

    return encrypted_payloads, hmac_res


def create_blinded_route(
    hops: list[PublicKey],
) -> tuple[PublicKey, list[PublicKey], list[bytes], bytes]:
    blinded_node_ids = []
    encrypted_datas = []

    secret = os.urandom(33)
    ephemeral_key = PrivateKey()
    ephemeral_pubkey = ephemeral_key.pubkey

    # First ephemeral pubkey is returned for use by sender
    first_ephemeral_pubkey = ephemeral_pubkey

    for i, hop in enumerate(hops):
        # Shared secret: ss(i) = >>>H(N(i) * e(i))<<< = H(k(i) * E(i))
        ss = hop.node_id().ecdh(ephemeral_key.private_key)

        # Blinded node id: B(i) = HMAC256("blinded_node_id", ss(i)) * N(i)
        blinded_node_id = hop.node_id().tweak_mul(
            hmac.new(b"blinded_node_id", ss, sha256).digest()
        )
        blinded_node_ids.append(blinded_node_id)

        # Get data to encrypt
        data_to_encrypt: EncryptedData
        is_recipient = i == len(hops) - 1
        if is_recipient:
            data_to_encrypt = EncryptedData(secret=secret)
        else:
            data_to_encrypt = EncryptedData(next_node_id=hops[i + 1].node_id())

        # Encrypt data
        # rho(i) = HMAC256("rho", ss(i))
        rho = hmac.new(b"rho", ss, sha256).digest()
        encrypted_data = ChaCha20_Poly1305.new(key=rho, nonce=bytes(12)).encrypt(
            data_to_encrypt.encode()
        )
        encrypted_datas.append(encrypted_data)

        # Compute next ephemeral key
        # e(i+1) = SHA256(E(i) || ss(i)) * e(i)
        ephemeral_key = PrivateKey(
            ephemeral_key.tweak_mul(sha256(ephemeral_pubkey.serialize() + ss).digest())
        )
        ephemeral_pubkey = ephemeral_key.pubkey

    # Skip the first blinded node id on return because it's the introduction node
    blinded_node_ids = blinded_node_ids[1:]

    return (first_ephemeral_pubkey, blinded_node_ids, encrypted_datas, secret)


def create_onion_packet(
    hops: list["Node"],
    intoduction_node_id: PublicKey,
    first_blinding_ephemeral_pubkey: PublicKey,
    blinded_node_ids: list[PublicKey],
    encrypted_datas: list[bytes],
) -> OnionPacket:
    route = [hop.node_id() for hop in hops] + [intoduction_node_id] + blinded_node_ids

    # Get keys
    onion_keys, first_ephemeral_pubkey = create_onion_keys(route)
    assert len(onion_keys) == len(route)

    # Get payloads
    payloads = create_payloads(
        hops,
        intoduction_node_id,
        first_blinding_ephemeral_pubkey,
        blinded_node_ids,
        encrypted_datas,
    )
    assert len(payloads) == len(route)

    # Fix packet length
    packet_length = sum([payload.encoded_length() + 32 for payload in payloads])
    if packet_length <= 1300:
        packet_length = 1300
    else:
        raise Exception("Packet too large")

    # Generate filler
    filler = create_filler(packet_length, payloads, onion_keys)
    assert len(filler) == sum(
        [payload.encoded_length() + 32 for payload in payloads[:-1]]
    )

    # Layer onion encrypted payloads
    encrypted_payloads, hmac_res = create_onion_payloads(
        packet_length, payloads, onion_keys, filler
    )

    return OnionPacket(first_ephemeral_pubkey, encrypted_payloads, hmac_res)


def forward_onion(
    my_private_key: PrivateKey,
    onion_packet: OnionPacket,
    blinding_point: PublicKey | None,
    is_recipient: bool,
) -> tuple[PublicKey | None, OnionPacket, PublicKey | None, bytes | None]:
    sphinx_privkey = my_private_key
    # If we're a node in a blinded hop, our onion has been encrypted
    # with our blinded node id. We need to tweak our private key by the same
    # factor our node id has been blinded with to be able to decrypt.
    if blinding_point:
        # Shared secret (for blinding): ss = H(N(i) * e(i)) = H(k(i) * E(i))
        blind_ss = blinding_point.ecdh(my_private_key.private_key)
        # B(i) = HMAC256("blinded_node_id", ss(i)) * N(i)
        # b(i) = HMAC256("blinded_node_id", ss(i)) * k(i)
        sphinx_privkey = PrivateKey(
            sphinx_privkey.tweak_mul(
                hmac.new(b"blinded_node_id", blind_ss, sha256).digest()
            )
        )

    ephemeral_pubkey = onion_packet.ephemeral_pubkey
    # Shared secret (for onion): ss = H(N(i) * e(i)) = H(k(i) * E(i))
    # E(i): ephemeral point in onion packet
    # N(i): our possibly blinded node id (sender used this to encrypt onion)
    # k(i): our private key (should have been tweaked if we're a blinded node)
    sphinx_ss = ephemeral_pubkey.ecdh(sphinx_privkey.private_key)
    keys = OnionKeys(sphinx_ss)

    # Verify hmac
    hmac_res = hmac.new(keys.mu, onion_packet.payloads, sha256).digest()
    assert hmac_res == onion_packet.hmac

    # Decrypt payloads
    cipher = ChaCha20_Poly1305.new(key=keys.rho, nonce=bytes(12))
    # encrypt/decrypt is the same for a prng cipher, makes creating the
    # packet extension easier
    decrypted_payloads = cipher.encrypt(onion_packet.payloads)

    # Get values from onion layer
    payload_length = int.from_bytes(decrypted_payloads[:1])
    decrypted_payloads = decrypted_payloads[1:]

    my_payload = Payload.decode(decrypted_payloads[:payload_length])
    decrypted_payloads = decrypted_payloads[payload_length:]

    next_hmac = decrypted_payloads[:32]
    decrypted_payloads = decrypted_payloads[32:]

    # Form next packet payloads
    next_payload_extension = cipher.encrypt(bytes(my_payload.encoded_length() + 32))
    next_payloads = decrypted_payloads + next_payload_extension
    assert len(next_payloads) == len(onion_packet.payloads)

    # Find next node (and blinding point)
    next_node_id = None
    next_blinding_point = None
    secret = None
    if my_payload.current_blinding_point or blinding_point:
        assert my_payload.encrypted_data is not None
        assert not (my_payload.current_blinding_point and blinding_point)

        # Blinding point may be shared with us via:
        # 1. current_blinding_point in the onion if we're the introduction node
        # 2. blinding_point in a lightning message (e.g. update_add_htlc)
        #    if we're a blinded hop
        this_blinding_point = my_payload.current_blinding_point or blinding_point

        # Shared secret (for blinding): ss(i) = H(N(i) * e(i)) = >>>H(k(i) * E(i))<<<
        blind_ss = this_blinding_point.ecdh(my_private_key.private_key)
        rho = hmac.new(b"rho", blind_ss, sha256).digest()

        # Decrypt and extract values
        decrypted_data = ChaCha20_Poly1305.new(key=rho, nonce=bytes(12)).decrypt(
            my_payload.encrypted_data
        )
        data = EncryptedData.decode(decrypted_data)
        next_node_id = data.next_node_id
        secret = data.secret

        # E(i+1) = H(E(i) || ss(i)) * E(i)
        next_blinding_point = this_blinding_point.tweak_mul(
            sha256(this_blinding_point.serialize() + blind_ss).digest()
        )
    else:
        # Non-blinded hops simply get the next node id from the onion
        assert my_payload.encrypted_data is None
        next_node_id = my_payload.next_node_id

    # Construct next onion
    next_ephemeral_pubkey = ephemeral_pubkey.tweak_mul(
        sha256(ephemeral_pubkey.serialize() + sphinx_ss).digest()
    )
    next_onion_packet = OnionPacket(next_ephemeral_pubkey, next_payloads, next_hmac)

    return next_node_id, next_onion_packet, next_blinding_point, secret


class Node:
    def __init__(self):
        self.privkey = PrivateKey()

    def node_id(self) -> PublicKey:
        return self.privkey.pubkey

    def forward_onion(
        self,
        onion_packet: OnionPacket,
        blinding_point: PublicKey | None,
        is_recipient: bool,
    ) -> tuple[PublicKey | None, OnionPacket, PublicKey | None, bytes | None]:
        return forward_onion(
            self.privkey,
            onion_packet,
            blinding_point,
            is_recipient,
        )


class TestOnion(unittest.TestCase):
    def test_onion(self):
        # Setup 5 nodes
        nodes = [Node() for _ in range(5)]

        # Create a blinded route from nodes 2-4
        blind_hops = [nodes[2], nodes[3], nodes[4]]
        introduction_node = blind_hops[0]
        (
            first_ephemeral_key,
            blinded_node_ids,
            encrypted_datas,
            initial_secret,
        ) = create_blinded_route(blind_hops)
        assert len(blinded_node_ids) == 2
        assert len(encrypted_datas) == 3

        # Node 0 creates onion to route from self, through introduction node,
        # through blinded route
        clear_hops = [nodes[1]]
        onion_packet = create_onion_packet(
            clear_hops,
            introduction_node.node_id(),
            first_ephemeral_key,
            blinded_node_ids,
            encrypted_datas,
        )

        # Forward through node 1
        next_node_id, onion_packet, blinding_point, secret = nodes[1].forward_onion(
            onion_packet, None, False
        )
        assert next_node_id.serialize() == nodes[2].node_id().serialize()
        assert blinding_point is None
        assert secret is None

        # Forward through node 2
        next_node_id, onion_packet, blinding_point, secret = nodes[2].forward_onion(
            onion_packet, blinding_point, False
        )
        assert next_node_id.serialize() == nodes[3].node_id().serialize()
        assert blinding_point is not None
        assert secret is None

        # Forward through node 3
        next_node_id, onion_packet, blinding_point, secret = nodes[3].forward_onion(
            onion_packet, blinding_point, False
        )
        assert next_node_id.serialize() == nodes[4].node_id().serialize()
        assert blinding_point is not None
        assert secret is None

        # Receive as node 4
        next_node_id, onion_packet, blinding_point, secret = nodes[4].forward_onion(
            onion_packet, blinding_point, True
        )
        assert next_node_id is None
        assert secret == initial_secret
