import calendar
import hashlib
import time
import base58
import unicodedata
import Crypto
import Crypto.Signature
import Crypto.Random
import Crypto.Cipher.AES
import Crypto.PublicKey
import bitcoin
import bitcoinlib
import hyconpy.mnemonic_hycon
import hyconpy.tx_pb2


def blake2b_hash(ob):
    if type(ob) == str:
        ob = ob.encode()
    blake2b_obj = hashlib.blake2b(digest_size=32)
    blake2b_obj.update(ob)
    return blake2b_obj.digest()


def public_key_to_address(public_key):
    hash_val = blake2b_hash(public_key)
    address = bytearray(20)
    for i in range(12, 32):
        address[i - 12] = hash_val[i]

    return bytes(address)


def address_to_string(public_key):
    return "H" + base58.b58encode(public_key) + address_checksum(public_key)


def address_to_byte_array(address):
    if address[0] != 'H':
        raise Exception("Address is invalid. Expected address to start with \'H\'")
    check = address[-4:]
    address = address[1:-4]
    out = base58.b58decode(address)
    if len(out) != 20:
        raise Exception("Address must be 20 bytes long")
    expected_check_sum = address_checksum(out)
    if expected_check_sum != check:
        raise Exception("Address hash invalid checksum "+str(check)+" expected \'"+str(expected_check_sum)+"\'")
    return out


def address_checksum(arr):
    hash_val = blake2b_hash(arr)
    str_val = base58.b58encode(hash_val)
    str_val = str_val[:4]
    return str_val


def zero_pad(input_string, length):
    return ("0"*length+input_string)[-length:]


def hycon_to_string(val: int):
    natural = val / 1000000000
    subnum = val % 1000000000
    if subnum == 0 :
        return str(natural)
    decimals = str(subnum)
    while len(decimals) < 9:
        decimals = "0" + decimals

    while decimals[-1] == '0':
        decimals = decimals[:-1]

    return str(natural) + "." + decimals


def hycon_from_string(val):  # (val: string): Long {
    if val=="" or val is None:
        return 0
    if val[-1] == ".":
        val += "0"
    arr = val.split(".")
    hycon = int(arr[0])*pow(10, 9)
    if len(arr) > 1:
        if len(arr[1]) > 9:
            arr[1] = arr[1][:9]
        subhycon = int(arr[1]) * pow(10, 9 - len(arr[1]))
        hycon += subhycon
    return hycon


BLOCK_SIZE = 16


def encoding_mnemonic(str_input: str):  # (str: string): string {
    return unicodedata.normalize("NFKD", str_input)


def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def encrypt(password, data):  # (password: string, data: string): { iv: string, encryptedData: string } {
    data = pad(data)
    key = blake2b_hash(password)
    iv = Crypto.Random.get_random_bytes(16)
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(data.encode())
    return dict(iv=''.join('{:02x}'.format(x) for x in iv), encrypted_data=encrypted_data)


def decrypt(password, iv, data):  # (password: string, iv: string, data: string): Buffer | boolean {

    key = blake2b_hash(password)
    iv_buffer = bytes.fromhex(iv)
    # data_buffer = bytearray.fromhex(data)
    decipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv_buffer)
    original_data = decipher.decrypt(data)
    return "".join(map(chr, unpad(original_data)))


def sign(tx_hash: bytes, private_key: str):
    msghash = tx_hash # bitcoin.electrum_sig_hash(tx_hash)
    z = bitcoin.hash_to_int(msghash)
    k = bitcoin.deterministic_generate_k(msghash, private_key)

    r, y = bitcoin.fast_multiply(bitcoin.G, k)
    s = bitcoin.inv(k, bitcoin.N) * (z + r * bitcoin.decode_privkey(private_key)) % bitcoin.N

    v, r, s = 27 + ((y % 2) ^ (0 if s * 2 < bitcoin.N else 1)), r, s if s * 2 < bitcoin.N else bitcoin.N - s
    if 'compressed' in bitcoin.get_privkey_format(private_key):
        v += 4
    hex_str_r = hex(r)[2:]
    if len(hex_str_r) < 64:
        hex_str_r = ((64 - len(hex_str_r)) * "0") + hex_str_r
    hex_str_s = hex(s)[2:]
    if len(hex_str_s) < 64:
        hex_str_s = ((64 - len(hex_str_s)) * "0") + hex_str_s
    signature = hex_str_r + hex_str_s
    recovery = v - 27
    return signature, recovery


def sign_tx(from_address: str, to_address: str, amount: str, miner_fee: str, nonce: int, private_key: str) -> dict:
    # (fromAddress: string, toAddress: string, amount: string, minerFee: string, nonce: number, privateKey: string):
    # { signature: string, recovery: number, newSignature: string, newRecovery: number } {
    from_ = address_to_byte_array(from_address)
    to_ = address_to_byte_array(to_address)
    itx = dict(amount=hycon_from_string(amount), fee=hycon_from_string(miner_fee), from_ = from_, nonce=nonce, to_=to_)
    signature = ""
    recovery = -1
    new_signature = ""
    new_recovery = -1
    itx = tx_pb2.Tx()
    itx.amount = hycon_from_string(amount)
    itx.fee = hycon_from_string(miner_fee)
    itx.from_ = from_
    itx.nonce = nonce
    itx.to = to_
    itx_new = tx_pb2.Tx()
    itx_new.networkid = "hycon"
    itx_new.amount = hycon_from_string(amount)
    itx_new.fee = hycon_from_string(miner_fee)
    itx_new.from_ = from_
    itx_new.nonce = nonce
    itx_new.to = to_
    proto_tx_new = itx_new.SerializeToString()
    tx_hash_new = blake2b_hash(proto_tx_new)
    signature, recovery = sign(tx_hash_new, private_key)
    new_sign = signature
    new_recovery = recovery
    if calendar.timegm(time.gmtime()) < 1544108400000:
        proto_tx = itx.SerializeToString()
        tx_hash = blake2b_hash(proto_tx)
        signature, recovery = sign(tx_hash, private_key)
        # .ecdsa_sign(tx_hash, raw=True)
        new_signature = new_sign
    else:
        signature = new_sign
        recovery = new_recovery

    return dict(signature=signature, recovery=recovery, newSignature=new_signature, newRecovery=new_recovery)


def sign_tx_with_hd_wallet(to_address, amount, miner_fee, nonce, private_extended_key, index):
    hd_key = bitcoinlib.keys.HDKey(import_key=private_extended_key)
    child_key = hd_key.subkey_for_path("m/44'/1397'/0'/0/" + str(index))
    private_key = child_key.private_byte
    public_key = child_key.public_byte

    if not check_public_key(public_key, child_key):
        raise Exception("publicKey from masterKey generated by hdkey is not equal publicKey generated by secp256k1")

    return sign_tx(address_to_string(public_key_to_address(public_key)),
                   to_address, amount, miner_fee, nonce, private_key)


def get_mnemonic(language):  # (language: string): string {
    return get_bip39_word_list(language)


def create_wallet(mnemonic_sentence, passphrase="", language="english"):
    # (mnemonic: string, passphrase: string = "", language: string = "english"):
    # { address: string, privateKey: string } {
    seed = bitcoinlib.mnemonic.Mnemonic(language).to_seed(mnemonic_sentence, passphrase)
    return derive_wallet(seed)


def create_hd_wallet(mnemonic, passphrase="", language="english"):
    # (mnemonic: string, passphrase: string = "", language: string = "english"): string {

    seed = bitcoinlib.mnemonic.Mnemonic(language).to_seed(mnemonic, passphrase)
    master_key = bitcoinlib.keys.HDKey.from_seed(seed)
    return master_key.wif(is_private=True)


def get_wallet_from_ext_key(private_extended_key, index):
    # (privateExtendedKey: string, index: number):
    # { address: string, privateKey: string } {

    try:
        hd_key = bitcoinlib.keys.HDKey(import_key=private_extended_key)
        child_key = hd_key.subkey_for_path("m/44'/1397'/0'/0/" + str(index))
        private_key = child_key.private_byte
        public_key = child_key.public_byte

        if not check_public_key(public_key, child_key):
            raise Exception("publicKey from masterKey generated by hdkey is not equal publicKey generated by secp256k1")

        return dict(address=address_to_string(public_key_to_address(public_key)),
                    private_key=private_key.hex())
    except Exception as error:
        raise Exception("Failed to getWalletFromExtKey : " + error)


def derive_wallet(seed, index=0):
    # (privateExtendedKey: string, index: number = 0):
    # { address: string, privateKey: string } {

    hd_key = bitcoinlib.keys.HDKey.from_seed(seed)
    child_key = hd_key.subkey_for_path("m/44'/1397'/0'/0/"+str(index))
    private_key = child_key.private_byte
    public_key = child_key.public_byte

    if not check_public_key(public_key, child_key):
        raise Exception("publicKey from masterKey generated by hdkey is not equal publicKey generated by secp256k1")

    return dict(address=address_to_string(public_key_to_address(public_key)),
                private_key=private_key.hex())


def get_bip39_word_list(language="english"):
    switcher = {
        "english": mnemonic_hycon.english,
        "korean": mnemonic_hycon.korean,
        "chinese_simplified": mnemonic_hycon.chinese_simplified,
        "chinese_traditional": mnemonic_hycon.chinese_traditional,
        "japanese": mnemonic_hycon.japanese,
        "french": mnemonic_hycon.french,
        "spanish": mnemonic_hycon.spanish,
        "italian": mnemonic_hycon.italian
    }
    print(switcher[language])
    return switcher[language]


def check_public_key(public_key, private_key):
    secp_pub_key = private_key.public_byte
    if public_key != secp_pub_key:
            return False
    return True
