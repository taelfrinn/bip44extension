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
		// /76h/0h/45h/6h
		var derived_node = btckey1.deriveHardened(76).deriveHardened(0).deriveHardened(45).deriveHardened(6);
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

	//var usernm = "faculty supreme other rebel protect";
	var usernm = "thunder comfort rose melt junk";
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
		// /76h/0h/45h/6h/0h
		var derived_node = btckey1.deriveHardened(76).deriveHardened(0).deriveHardened(45).deriveHardened(6).deriveHardened(0);
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
		// /76h/0h/45h/6h/1h
		var derived_node = btckey1.deriveHardened(76).deriveHardened(0).deriveHardened(45).deriveHardened(6).deriveHardened(1);
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
"mE8ESVwHgBMFK4EEAAoCAwSH+wplKKVyUhirzbn+ynb9wjfOMev5bgy//Q0Dp3+poz0984Uh53nV\n"+
"p7gzae1BSfTluS6ta1SiuCN0F38Wl/KjtB50aHVuZGVyIGNvbWZvcnQgcm9zZSBtZWx0IGp1bmuI\n"+
"cQQTEwgAGQUCSVwHgAIbAQQLCQgHBRUICQoDBBYCAwEACgkQh3rhedN9EcGPlAEA3bDPnm7PCZx5\n"+
"RO5XQhmS301bJL5OcgxYApBX9TAIuzkA/j4a9FHZmSsaQbJ2/+dbQrkutChDAqwGdfQkhImpsLmA\n"+
"uFMESVwHgBIFK4EEAAoCAwQukeiBAewvrkz183yhjPDViZpnAMLx0G4fjL6qvUNGNGwQlUrSVLJr\n"+
"Pc/WIQLTguwW1DCeO7G14QcbOcQkF9D9AwEIB4hhBBgTCAAJBQJJXAeAAhsMAAoJEId64XnTfRHB\n"+
"v/UBALzmsoLLXC++z+mX5dCgH4ASdwe4k3DJCCVxRUK6FI7XAP9QzVNl6aNmegVvseMopx+Y1XWG\n"+
"LiX3pReeImYOZ5s9ubhPBElcB4ATBSuBBAAKAgMEa2CCbUIKFuL8OfaxqH/tHwUFEPZi5LAmha1s\n"+
"/dXiJmmGFkc4uu95pOeg3/t2EyQ5uNY8pBs3cgPYDIxqFL7jeIjBBBgTCAAJBQJJXAeAAhsCAGoJ\n"+
"EId64XnTfRHBXyAEGRMIAAYFAklcB4AACgkQv7LNwP3jxRge/QD7B6sxwe20eYwdaaCnyPhTCI6/\n"+
"VtRkfyU2GKV0bHT+foIA/2euFvcW/pDLZv4S9RiaQD9GpfxgXT20mQ5F8l21vuTOR88A/R80u6GP\n"+
"1s6C/NM+XgdxRcmr7J3zAP77JyrMHTfsqaAfAP45BgUhgBY7VEr5a+T3vBI5YBNP37qPu98LgvvS\n"+
"98lXtg==\n"+
"=qDbE\n"+
"-----END PGP PUBLIC KEY BLOCK-----\n";

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
