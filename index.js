
var bitcoinjs = require('bitcoinjs-lib')
var bip39 = require('bip39')
var crypto = require('crypto')

function push_byte( prev_bytes, new_byte )
{
	var newb = new Buffer(1);
	newb[0] = new_byte;
	return Buffer.concat( [prev_bytes, newb ] );
}
function push_uint32( prev_bytes, new_byte )
{
	var newb = new Buffer(4);
	newb.writeUInt32BE( new_byte & 0xFFFFFFFF, 0, 4 );
	return Buffer.concat( [prev_bytes, newb ] );
}
function push_uint16( prev_bytes, new_byte )
{
	var newb = new Buffer(2);
	newb.writeUInt16BE( new_byte & 0xFFFF, 0, 2 );
	return Buffer.concat( [prev_bytes, newb ] );
}
function push_bytes( prev_bytes, new_bytes )
{
	//check type of prev_bytes, do various things
	if( typeof( new_bytes ) == "object" && Buffer.isBuffer(new_bytes) )
	{
		return Buffer.concat( [prev_bytes, new_bytes] );
	}
	// string
	else if( typeof( new_bytes ) == "string" || 
			(typeof( new_bytes ) == "object" && new_bytes.constructor === String ) )
	{
		prev_bytes = Buffer.concat( [prev_bytes, new Buffer (new_bytes)] );
	}
	// number
	else
	{
		throw new Error(" unknown type to push : " + typeof( new_bytes ) + new_bytes.constructor );
	}
	return prev_bytes;
}

var secp256k1_oid = new Buffer( "052b8104000a", 'hex' );

function dumb_sum( inp_bytes )
{
	var sum=0;
	for(var at = 0; at < inp_bytes.length  ;++at)
	{
		sum = (sum + inp_bytes[at]) & 0xFFFF ;
	}
	return sum;
}
function do_sha256_rounds( tohash, bytes_to_hash )
{
	var hasher = crypto.createHash('sha256');

	if( bytes_to_hash < tohash.length )
		bytes_to_hash = tohash.length;

	while( bytes_to_hash > 0 )
	{
		var thisround = tohash.length;
		if( thisround > bytes_to_hash)
		{
			hasher.update( tohash.slice(0, bytes_to_hash) );
		}
		else
		{
			hasher.update( tohash )
		}
		bytes_to_hash -= thisround;
	}
	return hasher.digest();//should return a Buffer
}
function continue_sha256_rounds( st )
{
	//expected params st.bytes_to_hash st.tohash st.maxprog
	//return value in st.digest
	//errors are thrown if happen
	//return value of false means "not done", true, means "done"
	if( !st.hasher)
	{
		//one time setup of hasher, one time roundup of bytes
		st.hasher = crypto.createHash('sha256');
		if( st.bytes_to_hash < st.tohash.length )
			st.bytes_to_hash = st.tohash.length;

	}

	var thisround_cnt=0;
	var thisround_max=500;
	while( st.bytes_to_hash > 0 )
	{
		++thisround_cnt;
		if( thisround_cnt >= thisround_max )
			return false;

		var thisround = st.tohash.length;
		if( thisround > st.bytes_to_hash)
		{
			st.hasher.update( st.tohash.slice(0, st.bytes_to_hash) );
		}
		else
		{
			st.hasher.update( st.tohash )
		}
		st.bytes_to_hash -= thisround;
		st.prog = st.maxprog - st.bytes_to_hash;
	}
	st.digest = st.hasher.digest();
	return true;
}

function incr_compute_key_packet_round( st, done_cb, err_cb, progress_cb, intertime )
{
	var isdone;
	try
	{	
		isdone = int_statemachine_compute_key_packet(st);
	}
	catch( err )
	{
		err_cb( err );
	}
	if( isdone )
	{
		done_cb( st.outp );
	}
	else
	{
		if( progress_cb )
			progress_cb( st.prog, st.maxprog );
		setTimeout( 
				function(){incr_compute_key_packet_round( st, done_cb, err_cb, progress_cb, intertime )} , intertime );
	}
}
function start_incr_compute_key_packet( hasprivate, isroot, can_encrypt, pk, s2kpassphrase,
		done_cb, err_cb, progress_cb, intertime )
{
	// return value will be passed to done if works, err will be passed the throwerror if not
	//setup context for repeat calls:
	// hasprivate, isroot, can_encrypt, pk, s2kpassphrase
	var st = 
	{
		"state" : 0,
		"hasprivate" : hasprivate,
		"isroot" : isroot,
		"can_encrypt" : can_encrypt,
		"pk" : pk,
		"s2kpassphrase" : s2kpassphrase,
	};
	setTimeout( function(){incr_compute_key_packet_round( st, done_cb, err_cb, progress_cb, intertime )} 
			, intertime);
}

function int_statemachine_compute_key_packet( st )
{
	//expects params in object st:
	// hasprivate, isroot, can_encrypt, st.pk, st.s2kpassphrase
	//returns true if done, false if needs more, throws if failure
	//progress lies in st.prog  max of prog in st.maxprog
	//result lies in st.outp
	// st.state: 0 -> startup, 1->hashing, 2->closedown
	st.prog = 0;
	st.maxprog = 31457280;
	if( ! st.state )
	{
		//open and init the state
		st.state = 0;
		var tag;
		if( st.isroot )
		{
			if( st.can_encrypt )
			{
				throw "Root keys cannot be ECDH, must be ECDSA";
			}
			tag = st.hasprivate ? 5 : 6;
		}
		else
		{
			tag = st.hasprivate ? 7 : 14;
		}

		st.overall_length = 0;//updated later up to 191
		st.outp = new Buffer(0);
		//tag +len pktheader
		var pkt_hdr = 0x80 | (tag<<2);
		st.outp = push_byte( st.outp,  pkt_hdr  );
		st.outp = push_byte( st.outp, st.overall_length  );               
		//version=0x04, creation time, algo=0x13,
		st.outp = push_byte( st.outp, 0x04 );                          //+1
		var timenow = 0x495C0780;
		st.outp = push_uint32(st.outp, timenow);                       //+4
		if(st.can_encrypt)
		{
			st.outp = push_byte( st.outp, 0x12 );                          //+1
		}else
		{
			st.outp = push_byte( st.outp, 0x13 );       
		}
		//OID mpi encoded = 05 2b 81 04 00 0a
		st.outp = push_bytes( st.outp, secp256k1_oid ); //+6

		var mpilen;
		//pubkey uncompressed mpi encoded (515 bits always)
		var pubk_b = st.pk.pub.toBuffer();
		//console.log('pubk_b.length = ' + pubk_b.length + '\n');
		//console.log( 'Value of pubk = ' + pubk_b.toString('hex')  + '\n type = ' + typeof( pubk_b));
		mpilen = 515;//8*pubk_b.size(); ignore acutal size??? 512 bits of any data + 3 bits to represent a "4"
		//fprintf(stderr,"pubkeybtyes=%zu mpilen=%zu\n", pubk_b.size(), mpilen );
		st.outp = push_uint16(st.outp, mpilen);                         //+2

		st.outp = push_bytes( st.outp, pubk_b); //+65

		if(st.can_encrypt)
		{
			//export ecdh key flags
			st.outp = push_bytes(st.outp, new Buffer("03010807", 'hex') );
			//// length=3, reserved 0x01, 0x08 = sha256, 0x07 = aes wrapping of keymat
		}

		if( st.hasprivate )
		{
			if( st.s2kpassphrase == "" )
			{
				var  s2k=0x00;                           //+1
				st.outp = push_byte(st.outp, s2k);

				//private key mpi encoded (up to 256 bits)
				var secr_b = st.pk.d.toBuffer(32);//secret bytes buffer
				var mpilen = 8*secr_b.length;
				st.outp = push_uint16(st.outp, mpilen );                        //+2
				st.outp = push_bytes( st.outp, secr_b ); //+32

				var csumb= dumb_sum( secr_b );
				st.outp = push_uint16(st.outp, csumb);                         // +2

				//jump to the final state?
				st.state = 2;
				return false;
			}
			else
			{
				//s2k output format
				// 0xFE 0d254 - indicates s2k is used
				// 0x09 indicates AES256
				// 0x03 - Iterated and Salted S2K specifier length = 1+1+8+1
				// 0x08 - hash algorithm = sha256
				// 8 byte init salt value
				// 0xEE  == 31457280  == 30*2^20
				// 		1 byte encoded hash iter byte_count over (salt|phrase)
				//       count = ((Int32)16 + (c & 15)) << ((c >> 4) + 6); (min count is full salt+phrase)
				// 16 bytes of aes 256 IV data
				// fully encrypted CFB block of length 54 = 2 len + 32 key + 20 bytes sha1hash value?
				// 				sha1 hash if of plaintext of the aeskey mpi(incl length)
				//ALGOR
				//	format MPI buffer of the clear length+key
				//	compute sha-1 hash over the above, append to mpi buffer, should be 54 bytes
				//  get 8 salt bytes from rand
				//	computer AES256 key using salt+passphrase, iterating input into sha256 till 31457280 bytes 
				//								hash-input fed in, leading to final hash which is aeskey
				//								shouldnt need multiple hashers, 32 bytes final enough for AES256
				//  get 16 IV bytes from rand
				//  encrypt mpibuffer using aes256 cfb, computed key, given IV
				//  OUTPUT: as above
				var secr_b = st.pk.d.toBuffer(32);//secret bytes buffer
				var mpilen = 8*secr_b.length;
				st.mpi_buffer_of_key = new Buffer(0);
				st.mpi_buffer_of_key = push_uint16(st.mpi_buffer_of_key, mpilen);
				st.mpi_buffer_of_key = push_bytes( st.mpi_buffer_of_key, secr_b );
				var sha1sum = crypto.createHash('sha1').update( st.mpi_buffer_of_key).digest();
				st.mpi_buffer_of_key = push_bytes( st.mpi_buffer_of_key, sha1sum );
				st.salt = crypto.randomBytes(8);
				//compute aes key
				var tohash = new Buffer(st.salt);
				tohash = push_bytes(tohash, st.s2kpassphrase);

				//ready for hashing rounds
				//setup parameters st.bytes_to_hash st.tohash
				st.bytes_to_hash = 31457280;
				st.tohash = tohash;
				st.state = 1;
				return false;
			}
		}
		st.state = 2;
		return false;
	}
	else if( st.state == 1 )
	{
		//continue hashing
		if( ! continue_sha256_rounds( st ) )
		{
			//not done yet
			return false;
		}

		//done should have digest now
		var aeskey = st.digest;
		{
			var  IVb = 	crypto.randomBytes(16);
			var IVb_dirty = new Buffer( IVb ); //another copy of iv buffer to use as the cfb buffer
			//fprintf(stderr,"IV = %s\n", sprint_hex_str(IVb).c_str() );
			var encryptor = crypto.createCipheriv( 'AES-256-CFB', aeskey, IVb_dirty );
			var mpi_buffer_encd = encryptor.update( st.mpi_buffer_of_key);
			st.outp = push_byte( st.outp, 0xFE );
			st.outp = push_byte( st.outp, 0x09 );
			st.outp = push_byte( st.outp, 0x03 );
			st.outp = push_byte( st.outp, 0x08 );
			st.outp = push_bytes( st.outp, st.salt );
			st.outp = push_byte( st.outp, 0xEE );
			st.outp = push_bytes( st.outp, IVb );
			st.outp = push_bytes( st.outp, mpi_buffer_encd );
		}

		st.state=2;
		return false;
	}
	else if( st.state == 2 )
	{
		//complete the packet
		st.overall_length = st.outp.length - 2;
		if( st.overall_length > 191 )
		{
			throw new Error( "overall_length %zu is too long for limit of 191\n" + st.overall_length );
		}
		st.outp[1] = st.overall_length;

		st.state = 3;//subseq calls will throw
		return true;
	}

	throw new Error("Unknown state - should never reach here");
}
function compute_key_packet( hasprivate, isroot, can_encrypt, pk, s2kpassphrase )
{
	var tag;
	if( isroot )
	{
		if( can_encrypt )
		{
			throw "Root keys cannot be ECDH, must be ECDSA";
		}
		tag = hasprivate ? 5 : 6;
	}
	else
	{
		tag = hasprivate ? 7 : 14;
	}

	var overall_length = 0;//updated later up to 191
	var outp = new Buffer(0);
	//tag +len pktheader
	var pkt_hdr = 0x80 | (tag<<2);
	outp = push_byte( outp,  pkt_hdr  );
	outp = push_byte( outp, overall_length  );               
	//version=0x04, creation time, algo=0x13,
	outp = push_byte( outp, 0x04 );                          //+1
	//uint32_t timenow = (uint32_t)time(0);
	// 495C0780  -- jan 1st 2009 -- all keys count as created at this time
	var timenow = 0x495C0780;
	outp = push_uint32(outp, timenow);                       //+4
	if(can_encrypt)
	{
		outp = push_byte( outp, 0x12 );                          //+1
	}else
	{
		outp = push_byte( outp, 0x13 );       
	}
	//OID mpi encoded = 05 2b 81 04 00 0a
	outp = push_bytes( outp, secp256k1_oid ); //+6
	
	var mpilen;
	//pubkey uncompressed mpi encoded (515 bits always)
	var pubk_b = pk.pub.toBuffer();
	//console.log('pubk_b.length = ' + pubk_b.length + '\n');
	//console.log( 'Value of pubk = ' + pubk_b.toString('hex')  + '\n type = ' + typeof( pubk_b));
	mpilen = 515;//8*pubk_b.size(); ignore acutal size??? 512 bits of any data + 3 bits to represent a "4"
	//fprintf(stderr,"pubkeybtyes=%zu mpilen=%zu\n", pubk_b.size(), mpilen );
	outp = push_uint16(outp, mpilen);                         //+2

	outp = push_bytes( outp, pubk_b); //+65

	if(can_encrypt)
	{
		//export ecdh key flags
		outp = push_bytes(outp, new Buffer("03010807", 'hex') );
		//// length=3, reserved 0x01, 0x08 = sha256, 0x07 = aes wrapping of keymat
	}

	if( hasprivate )
	{
		if( s2kpassphrase == "" )
		{
			var  s2k=0x00;                           //+1
			outp = push_byte(outp, s2k);

			//private key mpi encoded (up to 256 bits)
			var secr_b = pk.d.toBuffer(32);//secret bytes buffer
			var mpilen = 8*secr_b.length;
			outp = push_uint16(outp, mpilen );                        //+2
			outp = push_bytes( outp, secr_b ); //+32

			var csumb= dumb_sum( secr_b );
			outp = push_uint16(outp, csumb);                         // +2
		}
		else
		{
			//s2k output format
			// 0xFE 0d254 - indicates s2k is used
			// 0x09 indicates AES256
			// 0x03 - Iterated and Salted S2K specifier length = 1+1+8+1
			// 0x08 - hash algorithm = sha256
			// 8 byte init salt value
			// 0xEE  == 31457280  == 30*2^20
			// 		1 byte encoded hash iter byte_count over (salt|phrase)
	 		//       count = ((Int32)16 + (c & 15)) << ((c >> 4) + 6); (min count is full salt+phrase)
			// 16 bytes of aes 256 IV data
			// fully encrypted CFB block of length 54 = 2 len + 32 key + 20 bytes sha1hash value?
			// 				sha1 hash if of plaintext of the aeskey mpi(incl length)
			//ALGOR
			//	format MPI buffer of the clear length+key
			//	compute sha-1 hash over the above, append to mpi buffer, should be 54 bytes
			//  get 8 salt bytes from rand
			//	computer AES256 key using salt+passphrase, iterating input into sha256 till 31457280 bytes 
			//								hash-input fed in, leading to final hash which is aeskey
			//								shouldnt need multiple hashers, 32 bytes final enough for AES256
			//  get 16 IV bytes from rand
			//  encrypt mpibuffer using aes256 cfb, computed key, given IV
			//  OUTPUT: as above
			var secr_b = pk.d.toBuffer(32);//secret bytes buffer
			var mpilen = 8*secr_b.length;
			var mpi_buffer_of_key = new Buffer(0);
			mpi_buffer_of_key = push_uint16(mpi_buffer_of_key, mpilen);
			mpi_buffer_of_key = push_bytes( mpi_buffer_of_key, secr_b );
			var sha1sum = crypto.createHash('sha1').update( mpi_buffer_of_key).digest();
			mpi_buffer_of_key = push_bytes( mpi_buffer_of_key, sha1sum );
			var salt = crypto.randomBytes(8);
			//compute aes key
			var tohash = new Buffer(salt);
			tohash = push_bytes(tohash, s2kpassphrase);
			var aeskey = do_sha256_rounds( tohash, 31457280);
			var  IVb = 	crypto.randomBytes(16);
			var IVb_dirty = new Buffer( IVb ); //another copy of iv buffer to use as the cfb buffer
			//fprintf(stderr,"IV = %s\n", sprint_hex_str(IVb).c_str() );
			var encryptor = crypto.createCipheriv( 'AES-256-CFB', aeskey, IVb_dirty );
			var mpi_buffer_encd = encryptor.update( mpi_buffer_of_key);
			outp = push_byte( outp, 0xFE );
			outp = push_byte( outp, 0x09 );
			outp = push_byte( outp, 0x03 );
			outp = push_byte( outp, 0x08 );
			outp = push_bytes( outp, salt );
			outp = push_byte( outp, 0xEE );
			outp = push_bytes( outp, IVb );
			outp = push_bytes( outp, mpi_buffer_encd );
		}
	}

	overall_length = outp.length - 2;
	if( overall_length > 191 )
	{
		throw new Error( "overall_length %zu is too long for limit of 191\n" + overall_length );
	}
	outp[1] = overall_length;

	return outp;
}

function compute_key_fingerprint( key_packet )
{
	// 2 bytes header tag 
	// 1:v4 4:time 1:algo 6:OID 2:MPIlen 65:publickeyrawbytes
	var required_size = (1+4+1+6+2+65);
	//sanity checks
	if( key_packet.length < (required_size+2) )
	{
		throw new Error("key packet is too small to be valid" );
	}
	var pkttag = (key_packet[0] & 0x7F) >> 2;
	if( (pkttag != 5 && pkttag != 6 && pkttag != 7 && pkttag != 14) ||
			key_packet[0] & 0x03 ||  !(0x80 & key_packet[0]) )
	{
		throw new Error("Dont know how to analyze packet of header" + key_packet[0]  +  " for id fingerprint");
	}
	if( key_packet.length < (key_packet[1]+2) )
	{
		throw new Error("Packet is truncated: claims to be" + (key_packet[1]+2)+ " bytes" +
				", but only" + key_packet.length + " sent");
	}
	var algorith = key_packet[ 7 ];
	if( algorith == 19 )
		;
	else if( algorith == 18 )
	{
		required_size += 4;//expect exactly 4 bytes of flags?? 
	}
	else
	{
		throw new Error( "Unknown algorithm " +  algorith);
	}
	if( key_packet.length < required_size+2)
	{
		throw new Error("key packet is too small to be valid");
	}

	//A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
	//followed by the two-octet packet length, followed by the entire
	//Public-Key packet starting with the version field.  The Key ID is the
	//low-order 64 bits of the fingerprint.  Here are the fields of the
	//hash material, with the example of a DSA key:
	var ctx = crypto.createHash('sha1')
	
	var upbuf = new Buffer(1);
	upbuf[0] = 0x99;
	ctx.update( upbuf );
	upbuf[0] = (required_size >> 8)  & 0xFF;
	ctx.update( upbuf );
	upbuf[0] = required_size  & 0xFF;
	ctx.update( upbuf );

	ctx.update( key_packet.slice(2, 2+ required_size ));

	var outp = ctx.digest();
	return outp.slice( -8 );
}
function create_user_id_packet( username )
{
	var overall_length = username.length;
	if( overall_length > 191 )
		throw new Error("name too long, max is 191 bytes");
	var outp = new Buffer(2 + overall_length);
	//tag13 +len pktheader
	outp[0] = 0x80 | (13<<2);
	outp[1] = overall_length;                      
	outp.write(username, 2, overall_length);
	return outp;
}
function sign_root_secret_key_packet( certonly, rspck, usernm, pk)
{
	var outp = new Buffer(0);
	//format most of this_pkt_body(0x13, hattribs, attribs )
	var overall_length = 0;// + ?
	//tag2 +len pktheader
	var pkt_hdr = 0x80 | (2<<2);
	outp = push_byte( outp, pkt_hdr  );                      
	outp = push_byte( outp, overall_length  );               
	//0x04, class=0x13, pubka=0x13, hsha=0x08, 
	outp = push_bytes( outp, new Buffer( "04131308", 'hex') );  //+4
		//2L+hashed_subpks, 
	var subkl = 10+4+1+3+4+3;
	outp = push_uint16(outp, subkl);                         //+2
			//2.4 - time of creation of sig = now
	outp = push_byte( outp, 0x05 );                          //+1
	outp = push_byte( outp, 0x02 );                          //+1
	//uint32_t timenow = (uint32_t)time(0);//should we really use the current time?
	var timenow = 0x495C0780;
	outp = push_uint32( outp, timenow);                       //+4
			//27.1 = flags = 0x03 sign and cert
	outp = push_byte( outp, 0x02 );// 2 bytes                //+1
	outp = push_byte( outp, 0x1B );// subbkt 27              //+1
	if( certonly )
		outp = push_byte( outp, 0x01 );// cert only          //+1
	else
		outp = push_byte( outp, 0x03 );// cert and sign      //+1
			//11.3 = prefer sym algos = 9 8 7 
	outp = push_byte( outp, 0x04 );// 4 bytes                //+1
	outp = push_byte( outp, 0x0B );// subbkt 11              //+1
	outp = push_bytes( outp, new Buffer( "090807", 'hex') );// 9 8 7         //+3
			//21.4 = prefer hash algos = 8 9 10 3
	outp = push_byte( outp, 0x05 );// 5 bytes                //+1
	outp = push_byte( outp, 0x15 );// subbkt 21              //+1
	outp = push_bytes( outp, new Buffer( "08090a03", 'hex') );// 8 9 10 3  //+4
			//22.3 = prefer zip algos = 2 3 1 
	outp = push_byte( outp, 0x04 );// 4 bytes                //+1
	outp = push_byte( outp, 0x16 );// subbkt 22              //+1
	outp = push_bytes( outp, new Buffer( "020301", 'hex' ) );// 2 3 1         //+3

	//remember this point
	var hashable_body_so_far = outp.length - 2;
		//2L+unhashedsubpks
	subkl = 2+8;
	outp = push_uint16(outp, subkl);                         //+2
			//16.8 = issuer key id
	outp = push_byte( outp, 0x09 );// 9 bytes                //+1
	outp = push_byte( outp, 0x10 );// subbkt 16              //+1
	var parent_fing =  compute_key_fingerprint( rspck );
	outp = push_bytes( outp, parent_fing );  //+8
	//createsignaturehash: hashof:
	var hash_of_all;
	{
		var ctx = crypto.createHash('sha256')
	
			//0x99 + 2len, keypacketbody
		var upbuf = new Buffer(1);
		upbuf[0]=0x99;
		ctx.update( upbuf );

		var lenga = (1+4+1+6+2+65);
		if( rspck.length < lenga+2)
		{
			throw new Error("root packet be too small: want at least %zu, see only" +
					+ lenga+2 + " " + rspck.length + '\n' );
		}

		upbuf[0] = (lenga >> 8)  & 0xFF;
		ctx.update( upbuf );
		upbuf[0] = lenga  & 0xFF;
		ctx.update( upbuf );
	
		// add the public portion of the keypacketbody
		ctx.update( rspck.slice(2,2+lenga) );

			//0xB4 +4len + userid)
		upbuf[0] = 0xB4;
		ctx.update( upbuf );

		var uidlen = usernm.length;
		for( var at_x=4; at_x > 0 ; )
		{
			--at_x;
			upbuf[0] = ( uidlen >>( 8*at_x) ) & 0xFF;
			ctx.update( upbuf );
		}
		ctx.update( usernm );
			//this_pkt_body from verno thru end of hashed subpackets
		ctx.update( outp.slice( 2, hashable_body_so_far + 2) );
			//0x04 +0xFF + 4len of this signature packet data
		upbuf[0] = 0x04;
		ctx.update( upbuf );
		upbuf[0] = 0xFF;
		ctx.update( upbuf );
		for( var at_x=4;at_x>0; )
		{
			--at_x;
			upbuf[0] = ( hashable_body_so_far >>( 8*at_x) ) & 0xFF;
			ctx.update( upbuf );
		}
		hash_of_all = ctx.digest();
		//console.log( 'XXXXX hash_of_all =' + hash_of_all.toString('hex') + "\n" )
	}
	//2 octets of signed hash value start
	outp = push_bytes( outp, hash_of_all.slice(0,2) );  //+2
	
	//finish with signa ecdsa+sha256 hash output uncompressed (r+s only as 2 mpi's)
	var signa = pk.sign( hash_of_all );//should be rfc6979 determiknistic 

	if( signa )
	{
		var nBitsR = signa.r.bitLength();
		var nBitsS = signa.s.bitLength();
		if( nBitsR < 1 || nBitsR > 256 || nBitsS < 1 || nBitsS > 256 )
		{
			throw new Error("Strange size of r " + nBitsR  +" and S "+ nBitsS +" \n" );
		}
		outp = push_uint16(outp, nBitsR );                 //+2
		outp = push_bytes( outp, signa.r.toBuffer(32) );
		//console.log( 'XXXXX BitsR =' + signa.r.toBuffer(32).toString('hex') + "\n" )
		
		outp = push_uint16(outp, nBitsS );                        //+2
		outp = push_bytes( outp, signa.s.toBuffer(32) );
		//console.log( 'XXXXX BitsS =' + signa.s.toBuffer(32).toString('hex') + "\n" )
	}
	else
	{
		throw new Error("Failed to generate signature " );
	}
	overall_length = outp.length - 2;
	outp[1] = overall_length;
	return outp;
}

function int_sign_sub_secret_key_packet( embedded_recurse, rspck, sspck, pk, sk )
{
	var outp = new Buffer(0);
	//format most of this_pkt_body(0x18, hattribs, attribs )
	var overall_length = 0;// + ?
	//tag2 +len pktheader
	var pkt_hdr = 0x80 | (2<<2);
	outp = push_byte( outp, pkt_hdr  );                      
	outp = push_byte( outp, overall_length  );              //to be re-written later
	//0x04, class=0x18, pubka=0x13, hsha=0x08, 
	outp = push_byte( outp, 0x04 );                          //+1
	if( embedded_recurse )
		outp = push_byte( outp, 0x19 );                          //+1
	else
		outp = push_byte( outp, 0x18 );                          //+1
	outp = push_byte( outp, 0x13 );                          //+1
	outp = push_byte( outp, 0x08 );                          //+1

		//2L+hashed_subpks, 
	var subkl = 2+4;
	if(!embedded_recurse)
		subkl += 2+1;//usage flags length
	outp = push_uint16(outp, subkl);                         //+2
			//2.4 - time of creation of sig = now
	outp = push_byte( outp, 0x05 );                          //+1
	outp = push_byte( outp, 0x02 );                          //+1
	var timenow = 0x495C0780;
	outp = push_uint32(outp, timenow);                       //+4
	if( !embedded_recurse )
	{// no need for flags on the inside
			//27.1 = flags = 0x03 sign and cert 0x0C = encr and encr
		outp = push_byte( outp, 0x02 );// 2 bytes                //+1
		outp = push_byte( outp, 0x1B );// subbkt 27              //+1
		if( sk )
			outp = push_byte( outp, 0x02 );// sign only          //+1
		else
			outp = push_byte( outp, 0x0C );// encr and encr          //+1
	}

	//remember this point
	var hashable_body_so_far = outp.length - 2;

	var embedded_sig;
	if( sk )
	{
		embedded_sig = int_sign_sub_secret_key_packet( true, rspck, sspck, sk, null ).slice(2);
	}
		//2L+unhashedsubpks
	subkl = 2+8;
	if( sk)
	{
		subkl += embedded_sig.length + 2;
	}

	outp = push_uint16(outp, subkl );                         //+2
			//16.8 = issuer key id
	outp = push_byte( outp, 0x09 );// 9 bytes                //+1
	outp = push_byte( outp, 0x10 );// subbkt 16              //+1
	var parent_fing;
	var tofinger;
	if( embedded_recurse )
		tofinger = sspck;
	else
		tofinger = rspck;
	parent_fing = compute_key_fingerprint( tofinger );

	outp = push_bytes( outp, parent_fing );  //+8
	
	if( sk)
	{
		//if sk is sent, then lets embed a subpkt signature using the subkey
		outp = push_byte( outp, embedded_sig.length + 1 );
		outp = push_byte( outp, 0x20 );// subbkt 32              //+1
		outp = push_bytes( outp, embedded_sig );  
	}

	//createsignaturehash: hashof:
	var hash_of_all;
	{
		var ctx = crypto.createHash('sha256')
	
			//0x99 + 2len, keypacketbody
		var upbuf = new Buffer(1);
		upbuf[0]=0x99;
		ctx.update( upbuf );

		var lenga = (1+4+1+6+2+65);
		if( rspck.length < lenga+2)
		{
			throw new Error("root packet be too small: want at least %zu, see only" +
					+ lenga+2 + " " + rspck.length + '\n' );
		}

		upbuf[0] = (lenga >> 8)  & 0xFF;
		ctx.update( upbuf );
		upbuf[0] = lenga  & 0xFF;
		ctx.update( upbuf );
	
		// add the public portion of the keypacketbody
		ctx.update( rspck.slice(2,2+lenga) );

		// 0x99 + 2len + subkey body, same as above
		upbuf[0] = 0x99;
		ctx.update( upbuf );
		if( sspck[7] == 0x12 )//encrypting key
			lenga = (1+4+1+6+2+65+4);//four extra bytes for encrypting keys
		upbuf[0] = (lenga >> 8)  & 0xFF;
		ctx.update( upbuf );
		upbuf[0] = lenga  & 0xFF;
		ctx.update( upbuf );
		ctx.update( sspck.slice(2,2+lenga) );

			//this_pkt_body from verno thru end of hashed subpackets
		ctx.update( outp.slice( 2, hashable_body_so_far + 2) );
			//0x04 +0xFF + 4len of this signature packet data
		upbuf[0] = 0x04;
		ctx.update( upbuf );
		upbuf[0] = 0xFF;
		ctx.update( upbuf );
		for( var at_x=4;at_x>0; )
		{
			--at_x;
			upbuf[0] = ( hashable_body_so_far >>( 8*at_x) ) & 0xFF;
			ctx.update( upbuf );
		}
		hash_of_all = ctx.digest();
		//console.log( 'XXXXX hash_of_all =' + hash_of_all.toString('hex') + "\n" )
	}
	//2 octets of signed hash value start
	outp = push_bytes( outp, hash_of_all.slice(0,2) );  //+2
	
	//finish with signa ecdsa+sha256 hash output uncompressed (r+s only as 2 mpi's)
	var signa = pk.sign( hash_of_all );//should be rfc6979 determiknistic 
	if( signa )
	{
		var nBitsR = signa.r.bitLength();
		var nBitsS = signa.s.bitLength();
		if( nBitsR < 1 || nBitsR > 256 || nBitsS < 1 || nBitsS > 256 )
		{
			throw new Error("Strange size of r " + nBitsR  +" and S "+ nBitsS +" \n" );
		}
		outp = push_uint16(outp, nBitsR );                 //+2
		outp = push_bytes( outp, signa.r.toBuffer(32) );
		//console.log( 'XXXXX BitsR =' + signa.r.toBuffer(32).toString('hex') + "\n" )
		
		outp = push_uint16(outp, nBitsS );                        //+2
		outp = push_bytes( outp, signa.s.toBuffer(32) );
		//console.log( 'XXXXX BitsS =' + signa.s.toBuffer(32).toString('hex') + "\n" )
	}
	else
	{
		throw new Error("Failed to generate signature " );
	}
	overall_length = outp.length - 2;
	outp[1] = overall_length;
	return outp;
}
function sign_sub_secret_key_packet( rspck, sspck, pk, sk )
{
	return int_sign_sub_secret_key_packet( false, rspck,sspck, pk, sk );
}
function get_id_name( ck )
{
	var comprK = new bitcoinjs.ECKey(ck.d, true);
	//first 5 words of base58
	var addy = bitcoinjs.crypto.hash160( comprK.pub.toBuffer() );
	return bip39.entropyToMnemonic ( addy ).split(' ').slice(0,5).join(' ');
}

var CRC24_INIT = 0xB704CE;
var CRC24_POLY = 0x1864CFB;
function crc_octets( octets )
{
	var crc = CRC24_INIT;

	for( var atl=0; atl< octets.length ; ++atl ) 
	{
		crc ^= (octets[atl]) << 16;
		for (var i = 0; i < 8; i++)
		{
			crc <<= 1;
			if (crc & 0x1000000)
				crc ^= CRC24_POLY;
		}
	}
	return crc & 0xFFFFFF;
}
var _lcl_hdrs = 
{
	"message"   : "-----BEGIN PGP MESSAGE-----\n\n",
	"pubkey"    : "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n",
	"privkey"   : "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n",
	"signature" : "-----BEGIN PGP SIGNATURE-----\n\n"
};

var _lcl_trlrs =
{
	"message"   : "-----END PGP MESSAGE-----",
	"pubkey"    : "-----END PGP PUBLIC KEY BLOCK-----",
	"privkey"   : "-----END PGP PRIVATE KEY BLOCK-----",
	"signature" : "-----END PGP SIGNATURE-----"
};
function _lines_base64( inpbuf, maxl )
{
	var strfied = inpbuf.toString('base64');
	var ret = "";
	while( strfied.length > 0 )
	{
		var chompd;
		if( strfied.length > maxl )
		{
			chompd = strfied.slice(0,maxl);
			strfied = strfied.slice( maxl);
		}else
		{
			chompd = strfied;
			strfied = "";
		}
		ret += chompd;
		ret += '\n';
	}
	return ret;
}
function ascii_armor( ascii_armor_type, input_bytes )
{
	var ret = _lcl_hdrs[ascii_armor_type];
	var crc = crc_octets( input_bytes );
	ret += _lines_base64(input_bytes,76);
	if( ret.length > 0 && ret[ ret.length-1] != '\n' )
		ret+='\n';//ensure last byte is a newl
	var crcbytes = new Buffer(3);
	crcbytes[0] = (crc >> 16) & 0xFF;
	crcbytes[1] = (crc >> 8)  & 0xFF;
	crcbytes[2] = (crc)  & 0xFF;
	ret += "=" + crcbytes.toString('base64') + "\n" + _lcl_trlrs[ascii_armor_type] + "\n";
	return ret;
}

function create_gpg_binary_sexpr( 
		with_private, ck, ek, sk, s2kpassphrase )
{
	var root_ck_pkt = compute_key_packet( with_private, true, false, ck, s2kpassphrase );
	var usernm = get_id_name(ck);
	var uid_pkt = create_user_id_packet(usernm);
	var root_ck_sig = sign_root_secret_key_packet( true, root_ck_pkt, usernm, ck); 
	var ek_pkt = compute_key_packet( with_private, false, true, ek, s2kpassphrase );
	var ek_sig = sign_sub_secret_key_packet( root_ck_pkt, ek_pkt, ck, null ); 
	var sk_pkt = compute_key_packet( with_private, false, false, sk, s2kpassphrase );
	var sk_sig = sign_sub_secret_key_packet( root_ck_pkt, sk_pkt, ck, sk ); 
	return Buffer.concat( [ root_ck_pkt, uid_pkt, root_ck_sig, 
			ek_pkt, ek_sig, sk_pkt, sk_sig ] );
}

function bytes_entropy( password )
{
	var binpass = new Buffer( password, 'utf8' );
	var passlen = binpass.length;
	if(passlen<1)
	{
		return 0;
	}
	var counts = [];
	for (var k=0;  k< 256; ++k )
	{
		counts[k] = 0;
	}
	for (var b = 0; b < passlen; ++b )
	{
		counts[ binpass[b] ] += 1;
	}
	var sum = 0;
	for (var i=0;  i< 256; ++i )
	{
		if (counts[i] == 0)
		{
			continue;
		}
		var p = 1.0 * counts[i] / passlen;
		var lp = Math.log(p)/Math.log(2); // change of base formula, log base 2 of p

		sum -= p*lp;
	}

	return sum * passlen;
}
function create_wallet_gpg( root_hdnode, acct_no, s2kpassphrase ) 
{
	var has_private = false;
	var wrap = "pubkey";
	if( s2kpassphrase )
	{
		if( bytes_entropy(s2kpassphrase) < 75  )
			throw new Error( "tried to export secret gpg key with a too short passphrase - type a longer one" );
		has_private = true;
		wrap = "privkey";
	}
	acct_no = parseInt(acct_no);
	var ck_node = root_hdnode.deriveHardened(44).deriveHardened(0).deriveHardened(acct_no).deriveHardened(6);
	var ck = new bitcoinjs.ECKey(ck_node.privKey.d, false);
	var ek_node = ck_node.deriveHardened(0);
	var ek = new bitcoinjs.ECKey(ek_node.privKey.d, false);
	var sk_node = ck_node.deriveHardened(1);
	var sk = new bitcoinjs.ECKey(sk_node.privKey.d, false);

	var byt = create_gpg_binary_sexpr(has_private, ck, ek, sk, s2kpassphrase);
	return ascii_armor( wrap , byt );
}
function create_wallet_gpg_from_mnem( mnem, b39passphrase, acct_no, s2kpassphrase ) 
{
	bip39.mnemonicToEntropy( mnem );//to test in mnem is valid
	var byteshex = bip39.mnemonicToSeedHex(mnem, b39passphrase );
	var btcroot = bitcoinjs.HDNode.fromSeedHex(  byteshex );
	return create_wallet_gpg( btcroot, acct_no, s2kpassphrase );
}

function call_next( funccbs, timelimit, done_cb )
{
	if( funccbs.length == 0 )
	{
		return;
	}
	var isdone;
	next_call = funccbs.shift();
	try
	{
		isdone = next_call();
	}
	catch( err )
	{
		return done_cb( { "status": 0, "err" : err });
	}
	if( isdone )
		setTimeout( function(){call_next( funccbs, timelimit, done_cb )} , timelimit );
}

function start_create_wallet_gpg_from_mnem( 
		mnem, b39passphrase, acct_no, s2kpassphrase, cb, timeo, prog_cb )
{
	timeo = timeo || 100;
	bip39.mnemonicToEntropy( mnem );//to test in mnem is valid
	acct_no = parseInt(acct_no);
	var has_private = false;
	var wrap = "pubkey";
	if( s2kpassphrase )
	{
		if( bytes_entropy(s2kpassphrase) < 75  )
			throw new Error( "tried to export secret gpg key with a too short passphrase - type a longer one" );
		has_private = true;
		wrap = "privkey";
	}
	var byteshex = bip39.mnemonicToSeedHex(mnem, b39passphrase );
	var root_hdnode = bitcoinjs.HDNode.fromSeedHex(  byteshex );	
	
	var ck_node = root_hdnode.deriveHardened(44).deriveHardened(0).deriveHardened(acct_no).deriveHardened(6);
	var ck = new bitcoinjs.ECKey(ck_node.privKey.d, false);
	var ek_node = ck_node.deriveHardened(0);
	var ek = new bitcoinjs.ECKey(ek_node.privKey.d, false);
	var sk_node = ck_node.deriveHardened(1);
	var sk = new bitcoinjs.ECKey(sk_node.privKey.d, false);

	var root_ck_pkt; var uid_pkt; var root_ck_sig;
	var ek_pkt; var ek_sig; var sk_pkt; var sk_sig;

	var usernm = get_id_name(ck);

	var call_funct_set;
	function generic_err( e ){ throw e};
	var hasher_timeo = 1;
	var ttl_prog_max = 3* 31457280;
	var capt_prog = 0;
	function wrap_progr(x,y){ if(prog_cb) prog_cb( capt_prog+x, ttl_prog_max);}

	function s8() { var binbuf = Buffer.concat( [ root_ck_pkt, uid_pkt, root_ck_sig, 
							ek_pkt, ek_sig, sk_pkt, sk_sig ] );
					var resu = ascii_armor( wrap , binbuf );
					cb( { "status": true, "usernm" : usernm, "res" : resu} ); return true;}
	function s7() {sk_sig = sign_sub_secret_key_packet( root_ck_pkt, sk_pkt, ck, sk );return true; }
	function s6d(pk){ sk_pkt = pk;call_next( call_funct_set, timeo, cb );capt_prog += 31457280;}
	function s6() {start_incr_compute_key_packet( has_private, false, false, sk, s2kpassphrase,
			s6d, generic_err, wrap_progr, hasher_timeo); return false; }
	function s5() {ek_sig = sign_sub_secret_key_packet( root_ck_pkt, ek_pkt, ck, null );return true; }
	function s4d(pk){ek_pkt =pk; call_next( call_funct_set, timeo, cb ); capt_prog += 31457280;};
	function s4() {start_incr_compute_key_packet( has_private, false, true, ek, s2kpassphrase,
			s4d, generic_err, wrap_progr, hasher_timeo); return false; }
	function s3() {root_ck_sig = sign_root_secret_key_packet( true, root_ck_pkt, usernm, ck);return true; }
	function s2() {uid_pkt = create_user_id_packet(usernm); return true; }
	function s1d(pk) { root_ck_pkt=pk; call_next( call_funct_set, timeo, cb ); capt_prog += 31457280;}
	function s1() {start_incr_compute_key_packet( has_private, true, false, ck, s2kpassphrase,
			s1d, generic_err, wrap_progr, hasher_timeo); return false; }
	
	call_funct_set = [s1,s2,s3,s4,s5,s6,s7,s8];

	setTimeout( function(){call_next( call_funct_set, timeo, cb )}, timeo );
}

module.exports = {
	push_bytes : push_bytes,
	do_sha256_rounds :do_sha256_rounds,
	compute_key_packet : compute_key_packet ,
	compute_key_fingerprint : compute_key_fingerprint ,
	create_user_id_packet : create_user_id_packet, 
	sign_root_secret_key_packet : sign_root_secret_key_packet,
	sign_sub_secret_key_packet : sign_sub_secret_key_packet,
	ascii_armor : ascii_armor,
	create_wallet_gpg : create_wallet_gpg,
	create_wallet_gpg_from_mnem : create_wallet_gpg_from_mnem,
	start_create_wallet_gpg_from_mnem : start_create_wallet_gpg_from_mnem,
	bytes_entropy : bytes_entropy,
	get_id_name : get_id_name
};
