var bip44gpg = require('../index.js')
var bip39 = require('bip39')
var bitcoinjs = require('bitcoinjs-lib')
var pbkdf2 = require('pbkdf2-compat').pbkdf2Sync
var assert = require('assert')


describe('bip44gpg', function() {

	var byteshex;

	describe('Buffer', function()
	{
		byteshex = new Buffer(0);
		byteshex = bip44gpg.push_bytes( byteshex, new Buffer("\x01\x03\x04") )
		assert.equal( byteshex.length, 3);
		byteshex = bip44gpg.push_bytes( byteshex, "abc" );
		assert.equal( byteshex.length, 6);
	})



	var mnem;
	describe('hello, world!', function() {
			mnem = "runway smart water canyon illness system west sing woman once receive harsh";
			byteshex = bip39.mnemonicToEntropy( mnem );
			console.log( 'First result:\n ' +  mnem+ " \n "+  byteshex + "\n" );
			byteshex = bip39.mnemonicToSeedHex(mnem, null );
  			//byteshex = crypto.pbkdf2Sync( new Buffer(mnem,'hex'), 'mnemonic', 2048, 64, 'sha512').toString('hex');
			console.log( 'Seed hex = : ' + byteshex + "\n" );
			byteshexnull = bip39.mnemonicToSeedHex( "", "" );
			console.log( 'Null Seed hex = : ' + byteshexnull + "\n" );
			})

	var btckey1;
	describe('make a key now', function()
	{
//		{	
//			var fixt = '000102030405060708090a0b0c0d0e0f';
//			console.log( 'Make node from Seed hex = : ' + fixt + "\n" );
//			btckey1 = bitcoinjs.HDNode.fromSeedHex( fixt );
//			console.log( "fixt key = " + btckey1.toBase58() + "\n");
//			console.log( "shouldbe = " + 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi' + "\n");
//		}
		//now use bip32 to create a key	
		console.log( 'Make node from Seed hex = : ' + byteshex + "\n" );
		btckey1 = bitcoinjs.HDNode.fromSeedHex(  byteshex );
		console.log( "root key = " + btckey1.toBase58() + "\n");
	})

	describe('pbkdf2 problems', function()
	{
		var result = pbkdf2( 'password', 'salt', 1, 32, "sha512").toString('hex');
		console.log( ' unit pbkdf2 = ' + result + '\n');
		assert.equal( result, '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252' );
	})


	describe('do_sha256_rounds', function()
	{
		var temp = new Buffer("\x01\x02\x04\x00");
		var shahash = bip44gpg.do_sha256_rounds( temp, 100000 ).toString('hex');
		console.log( "Hash sha256 * 100000 bytes \n Over: " + temp.toString('hex') + "\n Is  : " + shahash + "\n" );
		assert.equal( shahash, '5f139504d71ccd2567860e9ea679f647180a17fbafdceceb8785a1884c9dc967' );
	})


	var root_cert_key_packet;
	var root_cert_key;
    describe('compute_key_packet', function()
	{
		//btckey1.privKey is an eckey
		// /44h/0h/45h/6h
		var derived_node = btckey1.deriveHardened(44).deriveHardened(0).deriveHardened(45).deriveHardened(6);
		root_cert_key = new bitcoinjs.ECKey(derived_node.privKey.d, false);
		root_cert_key_packet = bip44gpg.compute_key_packet( false, true, false, root_cert_key, "" );

		console.log( "Public root_cert_key_packet compute = \n" + root_cert_key_packet.toString('hex') );

		//btckey1.privKey is an eckey
		var packet2 = bip44gpg.compute_key_packet( true, true, false, root_cert_key, "" );

		console.log( "Private root_cert_key_packet compute = \n" + packet2.toString('hex') );

	})
    
	describe('compute_key_fingerprint', function()
	{
		var expect_keyid_hex = '11811f4e21395b37';
		console.log('key id should be ' + expect_keyid_hex + '\n');
		var fing = bip44gpg.compute_key_fingerprint(root_cert_key_packet).toString('hex');
		assert.equal( expect_keyid_hex, fing );
	})

	var usernm = "faculty supreme other rebel protect";
	describe('get_id_name', function()
	{
		var compa = bip44gpg.get_id_name(root_cert_key);
		assert.equal( usernm, compa);
	})

	var user_id_packet;
	describe('create_user_id_packet', function()
	{
		//user_id_packet = bip44gpg.create_user_id_packet("Maximus Decimus Beridius, General of the armies of the North");
		user_id_packet = bip44gpg.create_user_id_packet(usernm);
		
		console.log( "Name packet example: " + user_id_packet.toString('hex')  + '\n');
	})

	var root_cert_signature;
	describe('sign_root_secret_key_packet', function()
	{
		root_cert_signature = bip44gpg.sign_root_secret_key_packet( true, root_cert_key_packet, usernm, root_cert_key); 
		console.log( "Cert Sig packet: " + root_cert_signature.toString('hex')  + '\n');

	})

	var encrypting_subkey;
	var encrypting_subkey_packet;
    describe('compute_key_packet - subkey for encry', function()
	{
		//btckey1.privKey is an eckey
		// /44h/0h/45h/6h/0h
		var derived_node = btckey1.deriveHardened(44).deriveHardened(0).deriveHardened(45).deriveHardened(6).deriveHardened(0);
		encrypting_subkey = new bitcoinjs.ECKey(derived_node.privKey.d, false);
		encrypting_subkey_packet = bip44gpg.compute_key_packet( false, false, true, encrypting_subkey, "" );

		console.log( "Public encry key packet compute = \n" + encrypting_subkey_packet.toString('hex') );
	})
	var encrypting_subkey_packet_signa;
	describe('sign_sub_secret_key_packet - encry', function()
	{
		encrypting_subkey_packet_signa = bip44gpg.sign_sub_secret_key_packet( 
				root_cert_key_packet, encrypting_subkey_packet, root_cert_key, null ); 
		console.log( "Encry Sig packet: " + encrypting_subkey_packet_signa.toString('hex')  + '\n');

	})

	var signing_subkey;
	var signing_subkey_packet;
    describe('compute_key_packet - subkey for singing', function()
	{
		//btckey1.privKey is an eckey
		// /44h/0h/45h/6h/1h
		var derived_node = btckey1.deriveHardened(44).deriveHardened(0).deriveHardened(45).deriveHardened(6).deriveHardened(1);
		signing_subkey = new bitcoinjs.ECKey(derived_node.privKey.d, false);
		signing_subkey_packet = bip44gpg.compute_key_packet( false, false, false, signing_subkey, "" );

		console.log( "Public sub-sign key packet compute = \n" + signing_subkey_packet.toString('hex') );
	})
	var signing_subkey_packet_signa;
	describe('sign_sub_secret_key_packet - encry', function()
	{
		signing_subkey_packet_signa = bip44gpg.sign_sub_secret_key_packet( 
				root_cert_key_packet, signing_subkey_packet, root_cert_key, signing_subkey ); 
		console.log( "Sign Sig packet: " + signing_subkey_packet_signa.toString('hex')  + '\n');

	})

	var ascii_output_expected = 
"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"+
"\n"+
"mE8ESVwHgBMFK4EEAAoCAwRkZIqXqA5M0+ga0cy7c95jiANy+vuAmeLWNd/VEYUa2zpq7BDBknG8\n"+
"JjnIotlm0wSIM5wfmdSfBC5WMSFTwy7FtCNmYWN1bHR5IHN1cHJlbWUgb3RoZXIgcmViZWwgcHJv\n"+
"dGVjdIhxBBMTCAAZBQJJXAeAAhsBBAsJCAcFFQgJCgMEFgIDAQAKCRARgR9OITlbN0XMAQDUv6JC\n"+
"Yz0Oh37PAXSbpylSrfngs/XBqfo0w7xF5W1vjgD/QKtyqNqFqfqn5WaPdjCDgXzBAWIgk0wPQmjq\n"+
"+sWsgwW4UwRJXAeAEgUrgQQACgIDBMUHnrF7IyfX06q2L/nHI6cnTZM9TCTDsgcadYA2jh/HHkBj\n"+
"2aV4+P/gKW+8w01RPLUd1H5P3novV2KrN/16OMMDAQgHiGEEGBMIAAkFAklcB4ACGwwACgkQEYEf\n"+
"TiE5WzfIewD9Hf5d95R54obyH+RlfUDyWIwRWdZ9ctumwlIAHXmM6YgA/186ZbEJAZxg9umRsgd0\n"+
"nQvv+dwKSIcUtWhytbiW1ykpuE8ESVwHgBMFK4EEAAoCAwTsvqcxGhIBS3KtIpAGYQQsrAaDAmWg\n"+
"86BPN6RrrR+9bVh9sOk5ljugKdyVdpbhYjB+GmQh2Udk35+INJskljtYiMEEGBMIAAkFAklcB4AC\n"+
"GwIAagkQEYEfTiE5WzdfIAQZEwgABgUCSVwHgAAKCRDOt/H8tcYNaAnOAP4yLY1/CYI7dfh0cByR\n"+
"jD7LO5OlfPiG4lsMDdRjn4t/uwD/Qb4zSV9ocqWfKKZo9u86a1RZu1IiiirEPNBC0w2BpPaJ1QD9\n"+
"EM3Yv/Knp3y2p77rUxn0CUWAbNjEs4IVCejOdQIu504A/R53yZdE8DHaQCXZfcXN12vKCbqtP5t2\n"+
"UG6btS3AyK+Q\n"+
"=hpas\n"+
"-----END PGP PUBLIC KEY BLOCK-----\n" ;
	describe('bip44gpg.ascii_armor', function()
	{
		var combin = Buffer.concat( [
				root_cert_key_packet, user_id_packet, root_cert_signature, 
				encrypting_subkey_packet, encrypting_subkey_packet_signa, 
				signing_subkey_packet, signing_subkey_packet_signa ] );
		var output= bip44gpg.ascii_armor( "pubkey", combin);
		assert.equal(ascii_output_expected, output);
	})

	// test create_gpg_CES_private_key_binary_sexpr pubkey equal to above
	// test create_gpg_CES_private_key_binary_sexpr with a privkey with s2k
	// test create_wallet_gpg public to match all the above again
	describe('bip44gpg.create_wallet_gpg', function()
	{
		var output = bip44gpg.create_wallet_gpg(btckey1, 45, null );
		assert.equal(ascii_output_expected, output);
	})
	describe( "create_wallet_gpg_from_mnem" , function()
	{
		var output = bip44gpg.create_wallet_gpg_from_mnem( mnem, null, 45, null );
		console.log( output );
		assert.equal(ascii_output_expected, output);
		var output_priv = bip44gpg.create_wallet_gpg_from_mnem( mnem, null, 45, "ASuitablyLongs2kPassphraseFortesting" );
		console.log( output_priv );
		var output_priv2 = bip44gpg.create_wallet_gpg_from_mnem( mnem, "extar", 46, "ASuitablyLongs2kPassphraseFortesting" );
	})
})
