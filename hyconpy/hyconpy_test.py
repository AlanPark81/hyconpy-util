#!/usr/bin/python3
import unittest
import hyconpy


class TestHyconPy(unittest.TestCase):
    def test_encrypt_and_decrypt(self):
        data = "H497fHm8gbPZxaXySKpV17a7beYBF9Ut3"
        password = "t3sTP@sSw0rd!"

        ret_val = hyconpy.encrypt(password, data)

        self.assertFalse(ret_val.get("encrypted_data") == data)
        decrypted_data = hyconpy.decrypt(password, ret_val.get("iv"), ret_val.get("encrypted_data"))
        self.assertEqual(str(decrypted_data), data)
        result = hyconpy.decrypt(password + ".", ret_val.get("iv"), ret_val.get("encrypted_data"))
        self.assertIsNotNone(result)

    def test_sign_tx(self):
        result = hyconpy.sign_tx("H3N2sCstx81NvvVy3hkrhGsNS43834YWw",
                                 "H497fHm8gbPZxaXySKpV17a7beYBF9Ut3",
                                 "0.000000001",
                                 "0.000000001",
                                 1024,
                                 "e09167abb9327bb3748e5dd1b9d3d40832b33eb0b041deeee8e44ff47030a61d")

        self.assertEqual(("769f69d5a11f634dcb1e8b8f081c6b36b2e37b0a8f1b416314" 
                          "d5a3ceac27cc631e0ec12fd04473e8a168e2556897c55cd7f5e06f3ab917729176aa2e4b002d52"),
                         result.get("signature"))
        self.assertEqual(0, result.get("recovery"))
        self.assertEqual(("fd67de0827ccf8bc957eeb185ba0ea78aa1cd5cad74aea40244361ee7df"
                          "68e36025aebc4ae6b18628135ea3ef5a70ea3681a7082c44af0899f0f59"
                          "b50f2707b9"),
                         result.get("newSignature"))
        self.assertEqual(1, result.get("newRecovery"))

    def test_sign_tx_with_hd_wallet(self):
        result = hyconpy.sign_tx_with_hd_wallet("H3N2sCstx81NvvVy3hkrhGsNS43834YWw",
                                                "0.000000001",
                                                "0.000000001",
                                                1,
                                                ("xprv9s21ZrQH143K4bekgsnc9DtUYZzjjjT9MrcZfQHvKKq"
                                                 "7CkifHoAXC58LBFGjjpX6bSyp31mwTtbEMW6NAjV19QaQj6hVpz5Nphr3XiN5fbT"),
                                                0)
        self.assertEqual(("859e21720636cd0706a40ce6898cbd472071504053677496607136"
                          "c06be2b87378c65941c11ce098ba3ffdb1dc5c9302d6255ea2be3406556235c275c5c8a2b0"),
                         result.get("signature"))
        self.assertEqual(1, result.get("recovery"))
        self.assertEqual(("dbc4d77c31fbb69be70056b18dfe1e832585d65bd72284d7f503db9ff"
                          "806d6100e5823172b6b1b1f30ac7ce1895d4c98baa23331951da980a59b2cc2abd797bb"),
                         result.get("newSignature"))

        self.assertEqual(1, result.get("newRecovery"))

    def test_create_wallet(self):
        result = hyconpy.create_wallet("ring crime symptom enough erupt lady behave ramp apart settle citizen junk")
        self.assertEqual("HwTsQGpbicAZsXcmSHN8XmcNR9wXHtw7", result.get("address"))
        self.assertEqual("f35776c86f811d9ab1c66cadc0f503f519bf21898e589c2f26d646e472bfacb2", result.get("private_key"))

    def test_create_wallet_with_passphrase(self):
        result = hyconpy.create_wallet(
            "way prefer push tooth bench hover orchard brother crumble nothing wink retire", "TREZOR")
        self.assertEqual(result.get("address"), "H3fFn71jR6G33sAVMASDtLFhrq38h8FQ1")
        self.assertEqual(result.get("private_key"), "4c28ef543da7ee616d91ba786ce73ef02cf29818f3cdf5a4639771921a2cf843")

    def test_create_hd_wallet(self):
        result = hyconpy.create_hd_wallet("length segment syrup visa lava beach rain crush false reveal alone olympic")
        self.assertEqual(("xprv9s21ZrQH143K2gffZBzfnUUUjR5MfiQKNj1xXfwuHtxu7yz"
                          "APTMC6Gr6D5Krx2nPWVHoe6xDFTV6h6A2oZqXd5DbQowofFLS2fuk2RaU4tE"), result)

    def test_create_hd_wallet_with_passphrase(self):
        result = hyconpy.create_hd_wallet("length segment syrup visa lava beach rain crush false reveal alone olympic", "TREZOR")
        self.assertEqual(result, ("xprv9s21ZrQH143K4bekgsnc9DtUYZzjjjT9MrcZfQHvKKq7CkifHo"
                                  "AXC58LBFGjjpX6bSyp31mwTtbEMW6NAjV19QaQj6hVpz5Nphr3XiN5fbT"))

    def test_get_wallet_from_ext_key(self):
        result = hyconpy.get_wallet_from_ext_key(("xprv9s21ZrQH143K4bekgsnc9DtUYZzjjjT9MrcZfQHvKKq7Ckif"
                                                  "HoAXC58LBFGjjpX6bSyp31mwTtbEMW6NAjV19QaQj6hVpz5Nphr3XiN5fbT"), 1)
        self.assertEqual(result.get("address"), "H3cpQEhLs3pmwyTnv7PBHmux8CrRBA72d")
        self.assertEqual(result.get("private_key"), "1a6374f984be521f09a96c4842ec3e66a37e0239b95bd0e13d9632fa8f7dbc4a");


if __name__ == '__main__':
    unittest.main()
