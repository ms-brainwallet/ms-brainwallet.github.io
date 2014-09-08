// TODO - support TESTNET
// TODO - give a range and show a table full of the addresses
// TODO - find the chain index from a given p2sh address
// TODO - partially sign transactions
(function($){

    var key_derivation = 'public';
    var extpubkeys_from = 'manual';
    var pubkeys_from = 'manual';
    var pubkey_order = 0;
    var req_count = 2;
    var outof_count = 3;
    var gen_compressed = false;
    var gen_eckey = null;
    var gen_pt = null;
    var gen_ps_reset = false;
    var spend_from = 'redemption_script';
    var TIMEOUT = 600;
    var timeout = null;
    var raw_transaction = null;

    var coin = "btc_main";

    var PUBLIC_KEY_VERSION = 0;
    var PRIVATE_KEY_VERSION = 0x80;
    var ADDRESS_URL_PREFIX = 'http://blockchain.info/address/'
    var PERMUTATIONS = [[0,1,2], [0,2,1], [1,0,2], [1,2,0], [2,0,1], [2,1,0]];
    var SIGHASH_ALL = 1;

    function parseBase58Check(address) {
        var bytes = Bitcoin.Base58.decode(address);
        var end = bytes.length - 4;
        var hash = bytes.slice(0, end);
        var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
        if (checksum[0] != bytes[end] ||
            checksum[1] != bytes[end+1] ||
            checksum[2] != bytes[end+2] ||
            checksum[3] != bytes[end+3])
                throw new Error("Wrong checksum");
        var version = hash.shift();
        return [version, hash];
    }

    encode_length = function(len) {
        if (len < 0x80)
            return [len];
        else if (len < 255)
            return [0x80|1, len];
        else
            return [0x80|2, len >> 8, len & 0xff];
    }
    
    encode_id = function(id, s) {
        var len = encode_length(s.length);
        return [id].concat(len).concat(s);
    }

    encode_integer = function(s) {
        if (typeof s == 'number')
            s = [s];
        return encode_id(0x02, s);
    }

    encode_octet_string = function(s)  {
        return encode_id(0x04, s);
    }

    encode_constructed = function(tag, s) {
        return encode_id(0xa0 + tag, s);
    }

    encode_bitstring = function(s) {
        return encode_id(0x03, s);
    }

    encode_sequence = function() {
        sequence = [];
        for (var i = 0; i < arguments.length; i++)
            sequence = sequence.concat(arguments[i]);
        return encode_id(0x30, sequence);
    }

    function getEncoded(pt, compressed) {
       var x = pt.getX().toBigInteger();
       var y = pt.getY().toBigInteger();
       var enc = integerToBytes(x, 32);
       if (compressed) {
         if (y.isEven()) {
           enc.unshift(0x02);
         } else {
           enc.unshift(0x03);
         }
       } else {
         enc.unshift(0x04);
         enc = enc.concat(integerToBytes(y, 32));
       }
       return enc;
    }

    function getDER(eckey, compressed) {
        var curve = getSECCurveByName("secp256k1");
        var _p = curve.getCurve().getQ().toByteArrayUnsigned();
        var _r = curve.getN().toByteArrayUnsigned();
        var encoded_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01];

        var secret = integerToBytes(eckey.priv, 32);
        var encoded_gxgy = getEncoded(curve.getG(), compressed);
        var encoded_pub = getEncoded(gen_pt, compressed);

        return encode_sequence(
            encode_integer(1),
            encode_octet_string(secret),
            encode_constructed(0,
                encode_sequence(
                    encode_integer(1),
                    encode_sequence(
                        encoded_oid, //encode_oid(*(1, 2, 840, 10045, 1, 1)), //TODO
                        encode_integer([0].concat(_p))
                    ),
                    encode_sequence(
                        encode_octet_string([0]),
                        encode_octet_string([7])
                    ),
                    encode_octet_string(encoded_gxgy),
                    encode_integer([0].concat(_r)),
                    encode_integer(1)
                )
            ),
            encode_constructed(1, 
                encode_bitstring([0].concat(encoded_pub))
            )
        );
    }

    function pad(str, len, ch) {
        padding = '';
        for (var i = 0; i < len - str.length; i++) {
            padding += ch;
        }
        return padding + str;
    }

    function setErrorState(field, err, msg) {
        var group = field.closest('.controls');
        if (err) {
            group.addClass('has-error');
            group.attr('title',msg);
        } else {
            group.removeClass('has-error');
            group.attr('title','');
        }
    }

    // --- bip32 ---

    function keyDerivationUpdateLabel() {
      $('#keyDerivationMsg').text($('#key_derivation'+key_derivation).parent().attr('title'));
    }

    function updateKeyDerivation() {
        $('#extpubkeys_from_group').removeClass('hidden').addClass((key_derivation == 'public') ? '' : 'hidden');
        $('#extpub1_group').removeClass('hidden').addClass((key_derivation == 'public') ? '' : 'hidden');
        $('#extpub2_group').removeClass('hidden').addClass((key_derivation == 'public') ? '' : 'hidden');
        $('#extpub3_group').removeClass('hidden').addClass((key_derivation == 'public') ? '' : 'hidden');
        $('#extpublic_key_package').attr('readonly', (key_derivation == 'private' || extpubkeys_from == 'manual'));
        $('#bip32private_key1_group').removeClass('hidden').addClass((key_derivation == 'private') ? '' : 'hidden');
        $('#bip32private_key2_group').removeClass('hidden').addClass((key_derivation == 'private') ? '' : 'hidden');
        $('#bip32private_key3_group').removeClass('hidden').addClass((key_derivation == 'private') ? '' : 'hidden');
        if( key_derivation == 'public' ) {
            if( extpubkeys_from == 'manual' ) $("#extpub1").focus();
            else if( extpubkeys_from == 'extpublic_key_package' ) $("#extpublic_key_package").focus();
        } else if( key_derivation == 'private' ) $("#bip32private_key1").focus();

        // The generated private keys cannot be displayed if we're doing public-key derivation
        $('#genbip32private_key1_group').removeClass('hidden').addClass((key_derivation == 'private') ? '' : 'hidden');
        $('#genbip32private_key2_group').removeClass('hidden').addClass((key_derivation == 'private') ? '' : 'hidden');
        $('#genbip32private_key3_group').removeClass('hidden').addClass((key_derivation == 'private') ? '' : 'hidden');
        $('#bip32SpendP2SH').removeClass('hidden').addClass((key_derivation == 'private') ? '' : 'hidden');
    }

    function update_key_derivation() {
        key_derivation = $(this).attr('id').substring(15);
        keyDerivationUpdateLabel();
        updateKeyDerivation();

        $("#extpublic_key_package").val("");
        $("#genextpub1").val("");
        $("#genextpub2").val("");
        $("#genextpub3").val("");
        $("#genbip32private_key1").val("");
        $("#genbip32private_key2").val("");
        $("#genbip32private_key3").val("");

        clearTimeout(timeout);
        timeout = setTimeout(generate_extended_public_key_package, TIMEOUT);
    }


    function extpubkeysFromUpdateLabel() {
      $('#extpubkeysFromMsg').text($('#extpubkeys_from_'+extpubkeys_from).parent().attr('title'));
    }

    function updateExtpubkeysFrom() {
        $('#extpub1').attr('readonly', extpubkeys_from != 'manual');
        $('#extpub2').attr('readonly', extpubkeys_from != 'manual');
        $('#extpub3').attr('readonly', extpubkeys_from != 'manual');
        $('#extpublic_key_package').attr('readonly', extpubkeys_from != 'extpublic_key_package');
        if( extpubkeys_from == 'manual' ) $("#extpub1").focus();
        else if( extpubkeys_from == 'extpublic_key_package' ) $("#extpublic_key_package").focus();
    }

    function update_extpubkeys_from() {
        extpubkeys_from = $(this).attr('id').substring(16);
        extpubkeysFromUpdateLabel();
        updateExtpubkeysFrom();
    }

    function get_extended_key_set(k1, k2, k3) {
        var key1;
        try {
            var key1_str = $(k1).val();
            key1 = new BIP32(key1_str);
        } catch(err) {
            key1 = null;
        }

        var key2;
        try {
            var key2_str = $(k2).val();
            key2 = new BIP32(key2_str);
        } catch(err) {
            key2 = null;
        }

        var key3;
        try {
            var key3_str = $(k3).val();
            key3 = new BIP32(key3_str);
        } catch(err) {
            key3 = null;
        }

        return { key1: key1, key2: key2, key3: key3 };
    }

    function translate_extended_public_keys() {
        var t = ['public', 'private'];

        for( var i = 0; i < t.length; i++ ) {
            var keyset = get_extended_key_set(
                    (t[i] == 'public') ? "#extpub1" : "#bip32private_key1",
                    (t[i] == 'public') ? "#extpub2" : "#bip32private_key2",
                    (t[i] == 'public') ? "#extpub3" : "#bip32private_key3"
            );

            if( keyset.key1 !== null && 
               (   ( (keyset.key1.version == MAINNET_PUBLIC || keyset.key1.version == MAINNET_PRIVATE) && coin === 'btc_test' ) 
                || ( (keyset.key1.version == TESTNET_PUBLIC || keyset.key1.version == TESTNET_PRIVATE) && coin === 'btc_main' ) )
               ) {
                if( keyset.key1.version == MAINNET_PUBLIC ) keyset.key1.version = TESTNET_PUBLIC;
                else if( keyset.key1.version == MAINNET_PRIVATE ) keyset.key1.version = TESTNET_PRIVATE;
                else if( keyset.key1.version == TESTNET_PUBLIC ) keyset.key1.version = MAINNET_PUBLIC;
                else if( keyset.key1.version == TESTNET_PRIVATE ) keyset.key1.version = MAINNET_PRIVATE;
                keyset.key1.build_extended_public_key();
                keyset.key1.build_extended_private_key();
                $((t[i] == 'public') ? "#extpub1" : "#bip32private_key1").val(
                        (t[i] == 'public') ? keyset.key1.extended_public_key_string("base58") : keyset.key1.extended_private_key_string("base58"));
            }

            if( keyset.key2 !== null && 
               (   ( (keyset.key2.version == MAINNET_PUBLIC || keyset.key2.version == MAINNET_PRIVATE) && coin === 'btc_test' ) 
                || ( (keyset.key2.version == TESTNET_PUBLIC || keyset.key2.version == TESTNET_PRIVATE) && coin === 'btc_main' ) )
               ) {
                if( keyset.key2.version == MAINNET_PUBLIC ) keyset.key2.version = TESTNET_PUBLIC;
                else if( keyset.key2.version == MAINNET_PRIVATE ) keyset.key2.version = TESTNET_PRIVATE;
                else if( keyset.key2.version == TESTNET_PUBLIC ) keyset.key2.version = MAINNET_PUBLIC;
                else if( keyset.key2.version == TESTNET_PRIVATE ) keyset.key2.version = MAINNET_PRIVATE;
                keyset.key2.build_extended_public_key();
                keyset.key2.build_extended_private_key();
                $((t[i] == 'public') ? "#extpub2" : "#bip32private_key2").val(
                        (t[i] == 'public') ? keyset.key2.extended_public_key_string("base58") : keyset.key2.extended_private_key_string("base58"));
            }

            if( keyset.key3 !== null && 
               (   ( (keyset.key3.version == MAINNET_PUBLIC || keyset.key3.version == MAINNET_PRIVATE) && coin === 'btc_test' ) 
                || ( (keyset.key3.version == TESTNET_PUBLIC || keyset.key3.version == TESTNET_PRIVATE) && coin === 'btc_main' ) )
               ) {
                if( keyset.key3.version == MAINNET_PUBLIC ) keyset.key3.version = TESTNET_PUBLIC;
                else if( keyset.key3.version == MAINNET_PRIVATE ) keyset.key3.version = TESTNET_PRIVATE;
                else if( keyset.key3.version == TESTNET_PUBLIC ) keyset.key3.version = MAINNET_PUBLIC;
                else if( keyset.key3.version == TESTNET_PRIVATE ) keyset.key3.version = MAINNET_PRIVATE;
                keyset.key3.build_extended_public_key();
                keyset.key3.build_extended_private_key();
                $((t[i] == 'public') ? "#extpub3" : "#bip32private_key3").val(
                        (t[i] == 'public') ? keyset.key3.extended_public_key_string("base58") : keyset.key3.extended_private_key_string("base58"));
            }
        }

        generate_extended_public_key_package();
    }

    function generate_extended_public_key_package() {
        var keyset = get_extended_key_set(
                (key_derivation == 'public') ? "#extpub1" : "#bip32private_key1",
                (key_derivation == 'public') ? "#extpub2" : "#bip32private_key2",
                (key_derivation == 'public') ? "#extpub3" : "#bip32private_key3"
        );

        var count = 0;
        var bytes = [];

        if( keyset.key1 !== null ) {
            count |= 0x01;
            bytes = bytes.concat(Bitcoin.Base58.decode(keyset.key1.extended_public_key_string("base58")));
        }

        if( keyset.key2 !== null ) {
            count |= 0x02;
            bytes = bytes.concat(Bitcoin.Base58.decode(keyset.key2.extended_public_key_string("base58")));
        }

        if( keyset.key3 !== null ) {
            count |= 0x04;
            bytes = bytes.concat(Bitcoin.Base58.decode(keyset.key3.extended_public_key_string("base58")));
        }

        bytes = [count & 0xff].concat(bytes);

        var checksum = Crypto.SHA256(Crypto.SHA256(bytes, {asBytes: true}), {asBytes: true});
        bytes = bytes.concat(checksum.slice(0, 4));

        $("#extpublic_key_package").val(Crypto.util.bytesToHex(bytes));

        bip32_generate();
    }

    function parse_extended_public_key_package() {
        var extpackage = Crypto.util.hexToBytes($("#extpublic_key_package").val());

        var checksum = extpackage.slice(extpackage.length-4);
        if( Crypto.util.bytesToHex(Crypto.SHA256(Crypto.SHA256(extpackage.slice(0, extpackage.length-4), {asBytes: true}), {asBytes: true}).slice(0, 4)) 
            != Crypto.util.bytesToHex(checksum) ) {
            throw new Error("Invalid extended public key package");
        }

        var count = extpackage[0];
        if( count < 0 || count > 7 ) {
            throw new Error("Invalid extended public key package");
        }

        var p = 1;
        var keys = new Array();
        for( var i = 0; i < 3; i++ ) {
            if( ( count & (1 << i) ) != 0 ) {
                var k = new BIP32(Bitcoin.Base58.encode(extpackage.slice(p, p+82)));
                if( k.has_private_key ) throw new Error("Invalid extended public key package");
                keys.push(k);
                p += 82;
            } else {
                keys.push(null);
            }
        }

        for( var i = 0; i < 3; i++ ) {
            if( keys[i] != null ) {
                $("#extpub" + (i+1)).val(keys[i].extended_public_key_string("base58"));
            } else {
                $("#extpub" + (i+1)).val("");
            }
        }

        bip32_generate();
    }

    function onChangeExtendedPublicKey() {
        $("#extpublic_key_package").val("");
        clearTimeout(timeout);
        timeout = setTimeout(generate_extended_public_key_package, TIMEOUT);
    }
    
    function onChangeExtendedPublicKeyPackage() {
        $("#extpub1").val("");
        $("#extpub2").val("");
        $("#extpub3").val("");
        clearTimeout(timeout);
        timeout = setTimeout(parse_extended_public_key_package, TIMEOUT);
    }

    function onChangeExtendedPrivateKey() {
        clearTimeout(timeout);
        timeout = setTimeout(generate_extended_public_key_package, TIMEOUT);
    }

    function onChangeChainIndex() {
        $("#genextpub1").val("");
        $("#genextpub2").val("");
        $("#genextpub3").val("");
        $("#genbip32private_key1").val("");
        $("#genbip32private_key2").val("");
        $("#genbip32private_key3").val("");
        clearTimeout(timeout);
        timeout = setTimeout(bip32_generate, TIMEOUT);
    }

    function bip32_generate() {
        var key1, key2, key3;

        var keyset = get_extended_key_set(
                (key_derivation == 'public') ? "#extpub1" : "#bip32private_key1",
                (key_derivation == 'public') ? "#extpub2" : "#bip32private_key2",
                (key_derivation == 'public') ? "#extpub3" : "#bip32private_key3"
        );

        if( key_to_english == 'public' ) {
            if( keyset.key1 !== null && keyset.key1.has_private_key ) throw new Error("must be a public key");
            if( keyset.key2 !== null && keyset.key2.has_private_key ) throw new Error("must be a public key");
            if( keyset.key3 !== null && keyset.key3.has_private_key ) throw new Error("must be a public key");
        }

        if( key_to_english == 'private' ) {
            if( keyset.key1 !== null && !keyset.key1.has_private_key ) throw new Error("must be a private key");
            if( keyset.key2 !== null && !keyset.key2.has_private_key ) throw new Error("must be a private key");
            if( keyset.key3 !== null && !keyset.key3.has_private_key ) throw new Error("must be a private key");
        }

        $("#genextpub1").val("");
        $("#genextpub2").val("");
        $("#genextpub3").val("");
        $("#genbip32private_key1").val("");
        $("#genbip32private_key2").val("");
        $("#genbip32private_key3").val("");

        var chain_index = parseInt($("#chain_index").val(), 10);
        if( isNaN(chain_index) || chain_index < 0 || chain_index > 0x7fffffff ) return;

        var path_prefix = 'm/0/0/';

        if( keyset.key1 !== null ) {
            var d = keyset.key1.derive(path_prefix + chain_index);
            if( key_derivation == 'private') {
                $("#genbip32private_key1").val(d.extended_private_key_string());
            }
            $("#genextpub1").val(d.extended_public_key_string());
        }

        if( keyset.key2 !== null ) {
            var d = keyset.key2.derive(path_prefix + chain_index);
            if( key_derivation == 'private') {
                $("#genbip32private_key2").val(d.extended_private_key_string());
            }
            $("#genextpub2").val(d.extended_public_key_string());
        }

        if( keyset.key3 !== null ) {
            var d = keyset.key3.derive(path_prefix + chain_index);
            if( key_derivation == 'private') {
                $("#genbip32private_key3").val(d.extended_private_key_string());
            }
            $("#genextpub3").val(d.extended_public_key_string());
        }
    }

    function bip32CreateP2SH(setup_only) {
        if( setup_only === undefined ) setup_only = false;

        var keyset = get_extended_key_set("#genextpub1", "#genextpub2", "#genextpub3");

        if( keyset.key1 !== null ) 
            $("#pub1").val(Crypto.util.bytesToHex(keyset.key1.eckey.pub.getEncoded(true)));
        else 
            $("#pub1").val("");

        if( keyset.key2 !== null ) 
            $("#pub2").val(Crypto.util.bytesToHex(keyset.key2.eckey.pub.getEncoded(true)));
        else 
            $("#pub2").val("");

        if( keyset.key3 !== null ) 
            $("#pub3").val(Crypto.util.bytesToHex(keyset.key3.eckey.pub.getEncoded(true)));
        else 
            $("#pub3").val("");

        if( setup_only ) return;

        pubkey_order = 0;
        update_pubkey_order();
        generate_redemption_script();

        // Change the page.
        $('a[href="#generator"]').click();
    }

    function bip32SpendP2SH() {
        function compressed_private_key_base58(t, k) {
            var bytes = [0x80].concat(k.eckey.priv.toByteArrayUnsigned()).concat([1]);
            var checksum = Crypto.SHA256(Crypto.SHA256(bytes, {asBytes: true}), {asBytes: true}).slice(0, 4);
            t.val(Bitcoin.Base58.encode(bytes.concat(checksum)));
        }

        bip32CreateP2SH(true);

        var keyset = get_extended_key_set("#genbip32private_key1", "#genbip32private_key2", "#genbip32private_key3");

        if( keyset.key1 !== null )
            compressed_private_key_base58($("#txSec1"), keyset.key1);
        else
            $("#txSec1").val("");

        if( keyset.key2 !== null )
            compressed_private_key_base58($("#txSec2"), keyset.key2);
        else
            $("#txSec2").val("");

        if( keyset.key3 !== null )
            compressed_private_key_base58($("#txSec3"), keyset.key3);
        else
            $("#txSec3").val("");

        // Change the page.
        $('a[href="#tx"]').click();
        generate_redemption_script();

        $("#txRedemptionScript").val('');
        txOnChangeRedemptionScript();
    }

    // --- create ---

    function pubkeysFromUpdateLabel() {
        $('#pubkeysFromMsg').text($('#pubkeys_from_'+pubkeys_from).parent().attr('title'));
    }

    function updatePubkeysFrom() {
        $('#pub1').attr('readonly', pubkeys_from != 'manual');
        $('#pub2').attr('readonly', pubkeys_from != 'manual');
        $('#pub3').attr('readonly', pubkeys_from != 'manual');
        $('#redemption_script').attr('readonly', pubkeys_from != 'redemption_script');
        if( pubkeys_from == 'manual' ) $("#pub1").focus();
        else if( pubkeys_from == 'redemption_script' ) $("#redemption_script").focus();
    }

    function update_pubkeys_from() {
        pubkeys_from = $(this).attr('id').substring(13);
        pubkeysFromUpdateLabel();
        updatePubkeysFrom();
    }

    function reqUpdateLabel() {
      $('#reqMsg').text($('#req_'+req_count).parent().attr('title'));
    }

    function update_req_count() {
        req_count = parseInt($(this).attr('id').substring(4));
        reqUpdateLabel();
        clearTimeout(timeout);
        timeout = setTimeout(generate_redemption_script, TIMEOUT);
    }

    function update_outof() {
        $("#pub1_group").removeClass('hidden');
        $("#pub2_group").removeClass('hidden').addClass((outof_count < 2) ? 'hidden' : '');
        $("#pub3_group").removeClass('hidden').addClass((outof_count < 3) ? 'hidden' : '');
    }

    function outofUpdateLabel() {
      $('#outofMsg').text($('#outof_'+outof_count).parent().attr('title'));
    }

    function update_outof_count() {
        // 'of 1' and 'of 2' multisigs are non-standard, but we allow it with the warning that the tx 
        // is non-standard.
        outof_count = parseInt($(this).attr('id').substring(6))
        outofUpdateLabel();
        update_outof();
        clearTimeout(timeout);
        timeout = setTimeout(generate_redemption_script, TIMEOUT);
    }

    function update_pubkey_order() {
        if( pubkey_order == 0 ) $("#pubkey_order_current").html("Order #0 (sorted)");
        else                    $("#pubkey_order_current").html("Order #" + pubkey_order);
    }

    function pubkey_order_prev() {
        if( pubkey_order == 0 ) pubkey_order = 5;
        else                    pubkey_order -= 1;
        update_pubkey_order();
        generate_redemption_script();
    }

    function pubkey_order_next() {
        pubkey_order = (pubkey_order + 1) % 6;
        if( pubkey_order == 0 ) $("#pubkey_order_current").html("Order #0 (sorted)");
        else                    $("#pubkey_order_current").html("Order #" + pubkey_order);
        update_pubkey_order();
        generate_redemption_script();
    }

    function compare_arrays(a, b) {
        var i = 0, j = 0;

        while( i < a.length && j < b.length ) {
            if( a[i] < b[j] ) return -1;
            if( b[j] < a[i] ) return 1;
            i++;
            j++;
        }

        if( i == j ) return 0;
        if( i < j ) return -1;
        return 1;
    }

    function sort_keys(pub1, pub2, pub3) {
        var nums = [pub1, pub2, pub3];

        if( pub3 !== null && compare_arrays(nums[2], nums[1]) < 0 ) {
            var t = nums[1];
            nums[1] = nums[2];
            nums[2] = t;
        }

        if( pub2 !== null && compare_arrays(nums[1], nums[0]) < 0 ) {
            var t = nums[0];
            nums[0] = nums[1];
            nums[1] = t;
        }

        if( pub3 !== null && compare_arrays(nums[2], nums[1]) < 0 ) {
            var t = nums[1];
            nums[1] = nums[2];
            nums[2] = t;
        }

        return nums;
    }

    function permute_keys(sorted_keys, n) {
        var ret = [];

        for( var i = 0; i < sorted_keys.length; i++ ) {
            ret.push(sorted_keys[PERMUTATIONS[n][i]]);
        }

        return ret;
    }

    function determine_permutation(key_list) {
        var sorted_keys = sort_keys(key_list[0], key_list[1], key_list[2]);
        var order = [];

        for( var i = 0; i < key_list.length; i++ ) {
            for( var j = 0; j < sorted_keys.length; j++ ) {
                if( compare_arrays(key_list[i], sorted_keys[j]) == 0 ) {
                    order.push(j);
                }
            }
        }

        for( var i = 0; i < PERMUTATIONS.length; i++ ) {
            var good = true;
            for( var j = 0; j < PERMUTATIONS[i].length; j++ ) {
                if( PERMUTATIONS[i][j] != order[j] ) {
                    good = false;
                    break;
                }
            }
            if( good ) return i;
        }

        throw new Error("Invalid");
    }

    function generate_redemption_script() {
        var pub1_str = pad($('#pub1').val(), 65, '0');
        var pub1 = (outof_count >= 1) ? Crypto.util.hexToBytes(pub1_str) : null;

        var pub2_str = pad($('#pub2').val(), 65, '0');
        var pub2 = (outof_count >= 2) ? Crypto.util.hexToBytes(pub2_str) : null;

        var pub3_str = pad($('#pub3').val(), 65, '0');
        var pub3 = (outof_count == 3) ? Crypto.util.hexToBytes(pub3_str) : null;

        // Sort the keys, then use the pubkey_order to create the permutation
        var sorted_keys = permute_keys(sort_keys(pub1, pub2, pub3), pubkey_order);
        pub1 = sorted_keys[0];
        pub2 = sorted_keys[1];
        pub3 = sorted_keys[2];

        var pubkey1 = new Bitcoin.ECKey();
        if(pub1 !== null) {
            pubkey1.pub = pub1;
            pubkey1.pubKeyHash = Bitcoin.Util.sha256ripe160(pubkey1.pub);
        }

        var pubkey2 = new Bitcoin.ECKey();
        if(pub2 !== null) {
            pubkey2.pub = pub2;
            pubkey2.pubKeyHash = Bitcoin.Util.sha256ripe160(pubkey2.pub);
        }

        var pubkey3 = new Bitcoin.ECKey();
        if(pub3 !== null) {
            pubkey3.pub = pub3;
            pubkey3.pubKeyHash = Bitcoin.Util.sha256ripe160(pubkey3.pub);
        }

        // New versions of BitcoinJS-lib have createMultiSigOutputScript, but the one 
        // currently in brainwallet at github doesn't have it, so we must build the
        // script manually.
        var redemption_script = new Bitcoin.Script();

        redemption_script.writeOp([Bitcoin.Opcode.map["OP_1"], Bitcoin.Opcode.map["OP_2"], Bitcoin.Opcode.map["OP_3"]][req_count - 1]);
        
        var pubkeys = new Array(pub1, pub2, pub3);
        for( var i = 0; i < pubkeys.length && i < outof_count; i++ ) {
            redemption_script.writeBytes(pubkeys[i]);
        }

        redemption_script.writeOp(Bitcoin.Opcode.map["OP_1"] + (outof_count - 1));
        redemption_script.writeOp(Bitcoin.Opcode.map["OP_CHECKMULTISIG"]);

        var redemption_script_str = Crypto.util.bytesToHex(redemption_script.buffer);
        $("#redemption_script").val(redemption_script_str);

        update_p2sh_address();
    }

    function update_p2sh_address() {
        // Hash the script to produce the bitcoin address:
        var redemptionScriptHash160 = Bitcoin.Util.sha256ripe160(Crypto.util.hexToBytes($("#redemption_script").val()));
        var p2sh_addr = new Bitcoin.Address(redemptionScriptHash160);
        p2sh_addr.version = (coin == 'btc_main') ? 5 : 196;
        $("#addr").val('' + p2sh_addr);

        var qrCode = qrcode(3, 'M');
        var text = $('#addr').val();
        text = text.replace(/^[\s\u3000]+|[\s\u3000]+$/g, '');
        qrCode.addData(text);
        qrCode.make();

        $('#genAddrQR').html(qrCode.createImgTag(4));
        $('#genAddrURL').attr('href', ADDRESS_URL_PREFIX+p2sh_addr);
        $('#genAddrURL').attr('title', p2sh_addr);
    }

    function parse_redemption_script() {
        var redemption_script_bytes = Crypto.util.hexToBytes($("#redemption_script").val());
        var redemption_script = new Bitcoin.Script(redemption_script_bytes);

        var m = redemption_script.chunks[0] - Bitcoin.Opcode.map["OP_1"] + 1;
        if( m < 1 || m > 3 ) return;

        var slen = redemption_script.chunks.length;
        if( slen < 3 ) return;
        if( redemption_script.chunks[slen - 1] != Bitcoin.Opcode.map["OP_CHECKMULTISIG"] ) return;

        var n = redemption_script.chunks[slen - 2] - Bitcoin.Opcode.map["OP_1"] + 1;
        if( n < 1 || n > 3 ) return;

        // Temporary
        if( n != 3 ) {
            alert("Only m-of-3 multisignature transactions are supported.");
            return;
        }

        if( slen == (n + 3) ) {
            var new_keys = [redemption_script.chunks[1], redemption_script.chunks[2], redemption_script.chunks[3]];
            pubkey_order = determine_permutation(new_keys);
            if( n >= 1 ) $("#pub1").val(Crypto.util.bytesToHex(new_keys[0]));
            if( n >= 2 ) $("#pub2").val(Crypto.util.bytesToHex(new_keys[1]));
            if( n >= 3 ) $("#pub3").val(Crypto.util.bytesToHex(new_keys[2]));
            $("#req_" + m).click();
            $("#outof_" + n).click();
            update_pubkey_order();
            update_p2sh_address();
        }
    }

    function onChangePublicKey() {
        clearTimeout(timeout);
        timeout = setTimeout(generate_redemption_script, TIMEOUT);
    }

    function onChangeRedemptionScript() {
        clearTimeout(timeout);
        timeout = setTimeout(parse_redemption_script, TIMEOUT);
    }

    function initializePublicKeys() {
        $('#pub1').val('03d728ad6757d4784effea04d47baafa216cf474866c2d4dc99b1e8e3eb936e730');
        $('#pub2').val('02d83bba35a8022c247b645eed6f81ac41b7c1580de550e7e82c75ad63ee9ac2fd');
        $('#pub3').val('03aeb681df5ac19e449a872b9e9347f1db5a0394d2ec5caf2a9c143f86e232b0d9');
        $('#pub1').focus();
        pubkeysFromUpdateLabel();
        reqUpdateLabel();
        generate_redemption_script();
    }

    // --- converter ---

    var from = 'hex';
    var to = 'hex';

    function update_enc_from() {
        from = $(this).attr('id').substring(5);
        translate();
    }

    function update_enc_to() {
        to = $(this).attr('id').substring(3);
        translate();
    }

    function strToBytes(str) {
        var bytes = [];
        for (var i = 0; i < str.length; ++i)
           bytes.push(str.charCodeAt(i));
        return bytes;
    }

    function bytesToString(bytes) {
        var str = '';
        for (var i = 0; i < bytes.length; ++i)
            str += String.fromCharCode(bytes[i]);
        return str;
    }

    function isHex(str) {
        return !/[^0123456789abcdef:, ]+/i.test(str);
    }

    function isBase58(str) {
        return !/[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+/.test(str);
    }

    function isBase64(str) {
        return !/[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]+/.test(str) && (str.length % 4) == 0;
    }

    function issubset(a, ssv) {
        var b = ssv.trim().split(' ');
        for (var i = 0; i < b.length; i++) {
            if (a.indexOf(b[i].toLowerCase()) == -1 
                && a.indexOf(b[i].toUpperCase()) == -1)
            return false;
        }
        return true;
    }

    function autodetect(str) {
        var enc = [];
        if (isHex(str)) 
            enc.push('hex');
        if (isBase58(str))
            enc.push('base58');
        if (issubset(mn_words, str)) 
            enc.push('mnemonic');
        if (issubset(rfc1751_wordlist, str)) 
            enc.push('rfc1751');
        if (isBase64(str))
            enc.push('base64');
        if (str.length > 0)
            enc.push('text');
        return enc;
    }

    function update_toolbar(enc) {
        var reselect = false;
        $.each($('#enc_from').children(), function() {
            var id = $(this).children().attr('id').substring(5);
            var disabled = (enc && enc.indexOf(id) == -1);
            if (disabled && $(this).hasClass('active')) {
                $(this).removeClass('active');
                reselect = true;
            }
            $(this).attr('disabled', disabled);
        });
        if (enc && enc.length > 0 && reselect) {
            $('#from_' + enc[0]).click();//addClass('active');
            from = enc[0];
        }
    }

    function rot13(str) {
        return str.replace(/[a-zA-Z]/g, function(c) {
          return String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
        });
    }

    function enct(id) {
        return $('#from_'+id).parent().text();
    }

    function translate() {

        var str = $('#src').val();

        if (str.length == 0) {
          update_toolbar(null);
          $('#hint_from').text('');
          $('#hint_to').text('');
          $('#dest').val('');
          return;
        }

        text = str;

        var enc = autodetect(str);

        update_toolbar(enc);

        bytes = strToBytes(str);

        var type = '';

        if (bytes.length > 0) {
            if (from == 'base58') {
                try { 
                    var res = parseBase58Check(str); 
                    type = 'Check ver.' + res[0];
                    bytes = res[1];
                } catch (err) {
                    bytes = Bitcoin.Base58.decode(str);
                }
            } else if (from == 'hex') {
                bytes = Crypto.util.hexToBytes(str.replace(/[ :,]+/g,''));
            } else if (from == 'rfc1751') {
                try { bytes = english_to_key(str); } catch (err) { type = ' ' + err; bytes = []; };
            } else if (from == 'mnemonic') {
                bytes = Crypto.util.hexToBytes(mn_decode(str.trim()));
            } else if (from == 'base64') {
                try { bytes = Crypto.util.base64ToBytes(str); } catch (err) {}
            }

            var ver = '';
            if (to == 'base58') {
                if (bytes.length == 20 || bytes.length == 32) {
                    var addr = new Bitcoin.Address(bytes);
                    addr.version = bytes.length == 32 ? PRIVATE_KEY_VERSION : PUBLIC_KEY_VERSION;
                    text = addr.toString();
                    ver = 'Check ver.' + addr.version;
                } else {
                    text = Bitcoin.Base58.encode(bytes);
                }
            } else if (to == 'hex') {
                text = Crypto.util.bytesToHex(bytes);
            } else if (to == 'text') {
                text = bytesToString(bytes);
            } else if (to == 'rfc1751') {
                text = key_to_english(bytes);
            } else if (to == 'mnemonic') {
                text = mn_encode(Crypto.util.bytesToHex(bytes));
            } else if (to == 'base64') {
                text = Crypto.util.bytesToBase64(bytes);
            } else if (to == 'rot13') {
                text = rot13(str);
            }
        }

        $('#hint_from').text(enct(from) + type + ' (' + bytes.length + ' byte' + (bytes.length == 1 ? ')' : 's)'));
        $('#hint_to').text(enct(to) + ver + ' (' + text.length + ' character' + (text.length == 1 ? ')' : 's)'));
        $('#dest').val(text);
    }

    function onChangeFrom() {
        clearTimeout(timeout);
        timeout = setTimeout(translate, TIMEOUT);
    }

    function onInput(id, func) {
        $(id).bind("input keyup keydown keypress change blur", function() {
            if ($(this).val() != jQuery.data(this, "lastvalue")) {
                func();
            }
            jQuery.data(this, "lastvalue", $(this).val());
        });
        $(id).bind("focus", function() {
           jQuery.data(this, "lastvalue", $(this).val());
        });
    }

    // -- transactions --

    var txType = 'txBE';
    var txFrom = 'txFromSec';

    function spendFromUpdateLabel() {
        $('#spendFromMsg').text($('#spend_from_'+spend_from).parent().attr('title'));
    }

    function updateSpendFrom() {
        if(spend_from == 'redemption_script') {
            $("#txRedemptionScriptDiv").removeClass("hide");
            $("#txRawTransactionDiv").addClass("hide");
            $('#txUnspent').val('');
            $('#txUnspent').attr('disabled', false);
            $('#txGetUnspent').text("Download");
            $('#txBalance').val('');
            $('#txBalance').attr('disabled', false);
            $('#txFee').val('');
            $('#txFee').attr('disabled', false);
            $("#txAddDest").removeClass("hide");
            $("#txRemoveDest").removeClass("hide");
            $.each($('.txCC'), function() {
                $(this).find("#txDest").attr('disabled', false);
                $(this).find("#txValue").attr('disabled', false);
            });
            $("#txRedemptionScript").focus();
            txOnChangeRedemptionScript(false);
        } else {
            $("#txRedemptionScriptDiv").addClass("hide");
            $("#txRawTransactionDiv").removeClass("hide");
            $('#txUnspent').val('');
            $('#txUnspent').attr('disabled', true);
            $('#txGetUnspent').text("Verify");
            $('#txBalance').attr('disabled', true);
            $('#txFee').attr('disabled', true);
            $("#txAddDest").addClass("hide");
            $("#txRemoveDest").addClass("hide");
            $.each($('.txCC'), function() {
                $(this).find("#txDest").attr('disabled', true);
                $(this).find("#txValue").attr('disabled', true);
            });
            $("#txRawTransaction").focus();
        }
    }

    function update_spend_from() {
        spend_from = $(this).attr('id').substring(11);
        spendFromUpdateLabel();
        updateSpendFrom();
    }


    function txOnChangeSec() {
        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
    }

    function txOnChangeRedemptionScript(prompt_download) {
        var bytes = Crypto.util.hexToBytes($('#txRedemptionScript').val());
        var redemption_script = new Bitcoin.Script(bytes);

        // Hash the script to produce the bitcoin address:
        var redemptionScriptHash160 = Bitcoin.Util.sha256ripe160(redemption_script.buffer);
        var p2sh_addr = new Bitcoin.Address(redemptionScriptHash160);
        p2sh_addr.version = (coin == 'btc_main') ? 5 : 196;
        $("#txAddr").val('' + p2sh_addr);

        // Show/Hide private key spaces depending on M
        var m = redemption_script.buffer[0] - Bitcoin.Opcode.map["OP_1"] + 1;
        if( m < 1 || m > 3 ) {
            setErrorState($('#txRedemptionScript'), true, 'Redemption script is not valid');
            return;
        }

        $("#txSec1_group").removeClass('hidden');
        $("#txSec2_group").removeClass('hidden').addClass((m < 2) ? 'hidden' : '');
        $("#txSec3_group").removeClass('hidden').addClass((m < 3) ? 'hidden' : '');

        if(prompt_download) {
            txGetUnspent();
        } else {
            txRebuild();
        }
    }

    function txOnChangeRedemptionScriptDelayed() {
        $("#txAddr").val('');
        txRebuild();

        clearTimeout(timeout);
        timeout = setTimeout(function() { txOnChangeRedemptionScript(true); }, TIMEOUT);
    }

    function parseVarInt(bytes, o) {
        o = o || 0;
        var k = bytes[o];
        if( k < 0xfd ) {
            return { value: k, size: 1, data: [k] };                
        } else if( k == 0xfd ) {
            return { value: bytes[o+1] | (bytes[o+2] << 8), size: 3, data: bytes.slice(o, o+3) };
        } else if( k == 0xfe ) {
            return { value: bytes[o+1] | (bytes[o+2] << 8) | (bytes[o+3] << 16) | (bytes[o+4] << 24), size: 5, data: bytes.slice(o, o+5) };
        } else if( k == 0xff ) {
            throw 'Unsupported';
        }
    }

    function txOnChangeRawTransaction() {
        var bytes = Crypto.util.hexToBytes($('#txRawTransaction').val());
        var redemption_script = null;
        var bitcoin_script = null;
        var p2sh_addr = null;
        var m, n;
        var tx_for_hash = new Bitcoin.Transaction();
        raw_transaction = null;

        // Dissect the transaction looking for inputs. All inputs must have the same redemption script
        // and all inputs must be signed with the same keys.

        var offset = 0;
        var version = Crypto.util.bytesToWords(bytes.slice(offset, offset+4).reverse())[0];
        offset += 4;
        if(version != 1) {
            setErrorState($('#txRawTransaction'), true, 'Raw transaction is not valid');
            return;
        }

        var p = parseVarInt(bytes, offset);
        var num_inputs = p.value;
        offset += p.size;

        if(num_inputs < 1) {
            setErrorState($('#txRawTransaction'), true, 'Not enough inputs');
            return;
        }

        var inputs = [];
        for(var i = 0; i < num_inputs; i++) {
            var prevout_hash  = bytes.slice(offset, offset+32);
            var prevout_n     = Crypto.util.bytesToWords(bytes.slice(offset+32, offset+36).reverse())[0];

            p = parseVarInt(bytes, offset+36);
            var script_length = p.value;
            offset += p.size + 36;

            var script = bytes.slice(offset, offset+script_length);
            offset += script_length;

            // Don't care about sequence field
            offset += 4;

            // Parse the script. First byte must be 0x00
            if(script[0] != 0) {
                setErrorState($('#txRawTransaction'), true, 'Invalid input #' + i);
                return;
            }

            // The rest of the script must be data pushes
            var script_offset = 1;
            var pushes = [];
            while( script_offset < script.length ) {
                var op = script[script_offset++];
                if(op >= 1 && op <= 0x4b) {
                    pushes.push(script.slice(script_offset, script_offset+op));
                    script_offset += op;
                    continue;
                } else if(op == 0x4c) {
                    var size = script[script_offset++];
                    pushes.push(script.slice(script_offset, script_offset+size));
                    script_offset += size;
                    continue;
                } else if(op == 0x4d) {
                    var size = script[script_offset] | (script[script_offset] << 8);
                    script_offset += 2;
                    pushes.push(script.slice(script_offset, script_offset+size));
                    script_offset += size;
                    continue;
                } else {
                    setErrorState($('#txRawTransaction'), true, 'Invalid input #' + i);
                    return;
                }
            }

            // The last push is the redemption script. Verify it.
            if(i == 0) {
                redemption_script = pushes[pushes.length-1];

                bitcoin_script = new Bitcoin.Script(pushes[pushes.length-1]);

                var is_multisig = (bitcoin_script.buffer[bitcoin_script.buffer.length-1] == Bitcoin.Opcode.map["OP_CHECKMULTISIG"]);
                if(!is_multisig) {
                    setErrorState($('#txRawTransaction'), true, 'Invalid input #' + i + ': not multisig');
                    return;
                }

                m = bitcoin_script.buffer[0] - Bitcoin.Opcode.map["OP_1"] + 1;
                n = bitcoin_script.buffer[bitcoin_script.buffer.length-2] - Bitcoin.Opcode.map["OP_1"] + 1;
                if( m < 1 || m > n || n < 1 || n > 3 || bitcoin_script.chunks.length != (n + 3) ) {
                    setErrorState($('#txRawTransaction'), true, 'Invalid input #' + i + ': bad multisig');
                    return;
                }

                var hash160 = Bitcoin.Util.sha256ripe160(redemption_script);
                p2sh_addr = new Bitcoin.Address(hash160);
                p2sh_addr.version = (coin == 'btc_main') ? 5 : 196;

                // Extract the pubkeys (to verify signatures against)
                pubkeys = [bitcoin_script.chunks[1],
                           (n > 1) ? bitcoin_script.chunks[2] : null,
                           (n > 2) ? bitcoin_script.chunks[3] : null];

                for(var j = 0; j < pubkeys.length; j++) {
                    if(pubkeys[j] == null) continue;
                    var eckey = new Bitcoin.ECKey();
                    eckey.compressed = true;
                    eckey.pub = decompress_pubkey(pubkeys[j]);
                    eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(eckey.getPub());
                    pubkeys[j] = eckey;
                }

            } else {
                // all the other inputs have to have the exact same redemption script
                if(compare_arrays(redemption_script, pushes[pushes.length-1]) != 0) {
                    setErrorState($('#txRawTransaction'), true, 'Invalid input #' + i + ': not the same redemption script as input #0');
                    return;
                }
            }

            // The other pushes must be signatures for the public keys, but we can't verify them yet because we don't have 
            // the transaction hash that was used to sign this transaction.  The signature hash can't change (you can't 
            // add more outputs or inputs, and the scriptSigs aren't part of the signature hash), so we save them all for now
            // to be verified later.
            var signatures = pushes.slice(0, pushes.length - 1);
            for(var j = 0; j < signatures.length; j++) {
                var signature = signatures[j];
                var sign_type = signature[signature.length - 1];
                if(sign_type != SIGHASH_ALL) {
                    setErrorState($('#txRawTransaction'), true, 'Invalid input #' + i + ': signature ' + j + ' has invalid sign flag. Only SIGHASH_ALL supported.');
                    return;
                }

                signatures[j] = Crypto.util.bytesToHex(signature.slice(0, signature.length - 1));
            }

            inputs.push({
                'prevout_hash': endian(Crypto.util.bytesToHex(prevout_hash)),
                'prevout_n'   : prevout_n,
                'scriptSig'   : Crypto.util.bytesToHex(script),
                'signatures'  : signatures,
            });

            tx_for_hash.addInput(new Bitcoin.TransactionIn({outpoint: {hash: Crypto.util.bytesToBase64(prevout_hash), index: prevout_n}, script: script, sequence: 4294967295}));
        }

        var p = parseVarInt(bytes, offset);
        var num_outputs = p.value;
        offset += p.size;
        
        if(num_outputs < 1) {
            setErrorState($('#txRawTransaction'), true, 'Not enough outputs');
            return;
        }

        var outputs = [];
        for(var i = 0; i < num_outputs; i++) {
            var value_bytes = bytes.slice(offset, offset+8);
            offset += 8;

            var p = parseVarInt(bytes, offset);
            var script_length = p.value;
            offset += p.size;

            var script = bytes.slice(offset, offset+script_length);
            offset += script_length;

            // TODO show the output addresses and values
            var output_script = new Bitcoin.Script(script);
            if(output_script.getOutType() !== "Address") {
                setErrorState($('#txRawTransaction'), true, 'Invalid output #' + i + ': not a pay-to-pubkey-hash payment');
                return;
            }

            var address = new Bitcoin.Address(output_script.simpleOutHash());

            outputs.push({
                "address": '' + address,
                "value"  : parseFloat(Bitcoin.Util.formatValue(value_bytes.slice(0).reverse())),
            });

            tx_for_hash.addOutput(new Bitcoin.TransactionOut({ value: value_bytes, script: new Bitcoin.Script(script) }));
        }

        var lock_time = Crypto.util.bytesToWords(bytes.slice(offset, offset+4).reverse())[0];
        tx_for_hash.lock_time = lock_time;
        offset += 4;

        if(offset != bytes.length) {
            setErrorState($('#txRawTransaction'), true, 'Transaction has extra data');
            return;
        }

        // Verify all the signatures
        var must_match = 0;
        for(var i = 0; i < inputs.length; i++) {
            var hash_for_signature = tx_for_hash.hashTransactionForSignature(bitcoin_script, i, SIGHASH_ALL);

            var matched_pubkeys = Array.apply(null, new Array(pubkeys.length)).map(Number.prototype.valueOf, 0);
            var num_matched = 0;
            for(var j = 0; j < inputs[i].signatures.length; j++) {
                var found = null;

                for(var k = 0; k < pubkeys.length; k++) {
                    if( pubkeys[k] == null ) continue;

                    var signature = Crypto.util.hexToBytes(inputs[i].signatures[j]);
                    if(verify_signature(signature, hash_for_signature, pubkeys[k].getPubPoint())) {
                        found = k;
                        break;
                    }
                }

                if(found === null) {
                    setErrorState($('#txRawTransaction'), true, 'Input ' + i + ' has invalid signature');
                    return;
                }

                // key pubkeys[k] has matched for one signature, so it cannot be matched a second time
                if(matched_pubkeys[k] != 0) {
                    setErrorState($('#txRawTransaction'), true, 'Input ' + i + ' signs with the same key twice');
                    return;
                }

                matched_pubkeys[k] = 1;
                num_matched |= (1 << k);
            }

            if(i == 0) {
                must_match = num_matched;
            } else if(must_match != num_matched) {
                setErrorState($('#txRawTransaction'), true, 'Input ' + i + ' not signed with the same keys as input 0');
                return;
            }
        }

        $("#txRedemptionScript").val(Crypto.util.bytesToHex(redemption_script));

        setErrorState($('#txRawTransaction'), false, '');
        $("#txAddr").val('' + p2sh_addr);

        // Show (m - signed) boxes
        var left = m - inputs[0].signatures.length;
        $("#txSec1_group").removeClass('hidden');
        $("#txSec2_group").removeClass('hidden').addClass((left < 2) ? 'hidden' : '');
        $("#txSec3_group").removeClass('hidden').addClass((left < 3) ? 'hidden' : '');

        // set unspent to a fixed string
        $("#txUnspent").val(JSON.stringify({"unspent_outputs":inputs}, null, 4));
        $('#txBalance').val("unknown");
        $('#txFee').val("unknown");

        // setup destination addresses
        var list = $(document).find('.txCC');
        while(list.size() > 1) {
            list.last().remove();
            list = $(document).find('.txCC');
        }

        for(var i = 0; i < outputs.length; i++) {
            var dest;
            if(i == 0) {
                dest = $(document).find(".txCC").first();
            } else {
                txOnAddDest();
                dest = $(document).find(".txCC").last();
            }

            dest.find("#txDest").attr('disabled', true);
            dest.find("#txDest").val(outputs[i].address);
            dest.find("#txValue").attr('disabled', true);
            dest.find("#txValue").val(outputs[i].value);
        }

        $("#txAddDest").attr("disabled", true);
        $("#txRemoveDest").attr("disabled", true);

        // TODO be able to add signatures
        raw_transaction = tx_for_hash;
        txRebuild();
    }

    function txOnChangeRawTransactionDelayed() {
        $("#txAddr").val('');
        txRebuild();

        clearTimeout(timeout);
        timeout = setTimeout(function() { txOnChangeRawTransaction(); }, TIMEOUT);
    }


    function txSetUnspent(obj) {
        $('#txUnspent').val('');
        txUnspent = JSON.stringify(obj, null, 4);
        $('#txUnspent').val(txUnspent);

        var address = $('#txAddr').val();
        TX.parseInputs(txUnspent, address);

        var value = TX.getBalance();
        var fval = Bitcoin.Util.formatValue(value);
        var fee = parseFloat($('#txFee').val());
        $('#txBalance').val(fval);
        var value = Math.floor((fval-fee)*1e8)/1e8;
        $('#txValue').val(value);
        txRebuild();
    }

    function txVerifyUnspent(obj) {
        var text = JSON.stringify(obj)
        var address = $("#txAddr").val();
        try {
            var res = tx_parseBE(text, address);
        } catch(err) {
            try {
                var res = tx_parseBCI(text, address);
            } catch(err) {
                var res = tx_parseBBE(text, address);
            }
        }

        //This should be in prevout style as created by txOnChangeRawTransaction
        var inputs = JSON.parse($("#txUnspent").val())["unspent_outputs"];

        // Each of the used inputs needs to be "unspent", meanwhile sum up the inputs
        var in_total = BigInteger.ZERO.clone();
        for( var i = 0; i < inputs.length; i++ ) {
            var amount = BigInteger.ZERO.clone();
            var found = false;
            var input_prevout_hash = Crypto.util.hexToBytes(inputs[i].prevout_hash);
            var script_pub_key = null;

            for( var txid in res.unspenttxs ) {
                var prevout_hash = Crypto.util.hexToBytes(txid).reverse();

                for( var prevout_n in res.unspenttxs[txid] ) {
                    var unspent = res.unspenttxs[txid][prevout_n];
            
                    if( compare_arrays(input_prevout_hash, prevout_hash) == 0 && inputs[i].prevout_n == prevout_n ) {
                        found = true;
                        script_pub_key = unspent.script_pub_key;
                        amount = unspent.amount;
                        break;
                    }
                }

                if(found) break;
            }

            if(found) {
                inputs[i].amount = Bitcoin.Util.formatValue(amount);
                inputs[i].script_pub_key = script_pub_key;
                in_total = in_total.add(amount);
            } else {
                // Error, this input wasn't found
                alert("Invalid transaction: input " + i + " wasn't found. It's likely that input was invalid or has been spent already.");
                return;
            }
        }

        $("#txUnspent").val(JSON.stringify(inputs, null, 4));
        $("#txBalance").val(Bitcoin.Util.formatValue(in_total));

        // Sum up the outputs, subtract, display the fee
        var out_total = BigInteger.ZERO.clone();
        for( var i = 0; i < raw_transaction.outs.length; i++ ) {
            var out_amount = new BigInteger(Crypto.util.bytesToHex(raw_transaction.outs[i].value.slice(0).reverse()), 16);
            out_total = out_total.add(out_amount);
        }

        var fees = in_total.subtract(out_total);
        if(fees.compareTo(BigInteger.ZERO) < 0) {
            // Invalid tx! More outputs than inputs
            alert("Invalid transaction: there are more outputs than inputs. It is recommended that you do not sign this transaction.");
            return;
        }

        $("#txFee").val(Bitcoin.Util.formatValue(fees));

        alert("All inputs found as unspent. Double-check your outputs and fees before signing.");
    }

    function txUpdateUnspent() {
        txSetUnspent(JSON.parse($('#txUnspent').val()));
    }

    function txOnChangeUnspent() {
        clearTimeout(timeout);
        timeout = setTimeout(txUpdateUnspent, TIMEOUT);
    }

    function txGetUnspent() {
        var addr = $('#txAddr').val();

        var url = null;
        if(txType == 'txBCI') {
            url = 'http://blockchain.info/unspent?active=' + addr;
        } else if(txType == 'txBBE') {
            url = 'http://blockexplorer.com/q/mytransactions/' + addr;
        } else if(txType == 'txBE') {
            url = 'https://api.biteasy.com/blockchain/v1/addresses/' + addr + '/unspent-outputs';
        }

        url = prompt('Press OK to download transaction history:', url);
        if (url != null && url != "") {
            $.ajax({
                url: url,
                success: function(res) {
                    if(spend_from == "redemption_script") {
                        txSetUnspent(res);
                    } else {
                        txVerifyUnspent(res);
                    }
                },
                error:function (xhr, opt, err) {
                    alert(err);
                }
            });
        } else {
          txSetUnspent(JSON.parse($('#txUnspent').val()));
        }
    }

    function txOnChangeJSON() {
        var str = $('#txJSON').val();
        try {
          var sendTx = TX.fromBBE(str);
          $('txJSON').removeClass('has-error');
          var bytes = sendTx.serialize();
          var hex = Crypto.util.bytesToHex(bytes);
          $('#txHex').val(hex);
          setErrorState($('#txJSON'), false, '');
        } catch (err) {
          setErrorState($('#txJSON'), true, 'syntax error');
        }
    }

    function txOnChangeHex() {
        var str = $('#txHex').val();
        str = str.replace(/[^0-9a-fA-f]/g,'');
        $('#txHex').val(str);
        var bytes = Crypto.util.hexToBytes(str);
        var sendTx = TX.deserialize(bytes);
        var text = TX.toBBE(sendTx);
        $('#txJSON').val(text);
    }

    function txOnAddDest() {
        var list = $(document).find('.txCC');
        var clone = list.last().clone();
        clone.find('.help-inline').empty();
        clone.find('.control-label').text('Cc');
        var dest = clone.find('#txDest');
        var value = clone.find('#txValue');
        clone.insertAfter(list.last());
        onInput(dest, txOnChangeDest);
        onInput(value, txOnChangeDest);
        dest.val('');
        value.val('');
        $('#txRemoveDest').attr('disabled', false);
        return false;
    }

    function txOnRemoveDest() {
        var list = $(document).find('.txCC');
        if (list.size() == 2)
            $('#txRemoveDest').attr('disabled', true);
        list.last().remove();
        return false;
    }

    function txSent(text) {
        alert(text ? text : 'No response!');
    }

    function txKey(i) {
        setErrorState($('#txSec' + i), false, '');
        var sec = $('#txSec' + i).val();
        try {
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
        } catch (err) {
            if($("#txSec" + i).val() !== "") {
                setErrorState($('#txSec' + i), true, 'Not a valid private key');
            }
            return null;
        }

        var compressed = false;
        if (payload.length > 32) {
            payload.pop();
            compressed = true;
        }

        var eckey = new Bitcoin.ECKey(payload);
        eckey.setCompressed(compressed);
        return eckey;
    }

    function pubkey_matches_privkey(pubkey, eckey) {
        var isCompressed = (pubkey[0] == 0x02) || (pubkey[0] == 0x03);
        return compare_arrays( pubkey, eckey.getPubPoint().getEncoded(isCompressed) ) == 0;
    }

    function array_has_object(list, obj) {
        var x;
        for (x in list) {
            if (list.hasOwnProperty(x) && list[x] === obj) {
                return true;
            }
        }
        return false;
    }

    function txRebuild() {
        if(spend_from == 'redemption_script') {
            txRebuildFromRedemptionScript();
        } else {
            txRebuildFromRawTransaction();
        }

        //var qrCode = qrcode(10, 'L');
        //var data = Crypto.util.hexToBytes($('#txHex').val());
        //console.log(data.length);
        //qrCode.addData(data);
        //qrCode.make();
        //$('#txQR').html(qrCode.createImgTag(4, 0));
    }

    function txRebuildFromRedemptionScript() {
        var bytes = Crypto.util.hexToBytes($('#txRedemptionScript').val());
        var redemption_script = new Bitcoin.Script(bytes);
        var m = redemption_script.buffer[0] - Bitcoin.Opcode.map["OP_1"] + 1;
        var n = redemption_script.buffer[redemption_script.buffer.length-2] - Bitcoin.Opcode.map["OP_1"] + 1;

        var eckeyarr = [txKey(1), 
                        (m > 1) ? txKey(2) : null, 
                        (m > 2) ? txKey(3) : null];
        var eckeys = new Array();

        // Need to determine the order of the keys in the redemption script.
        // And build 'eckeys' in an order that matches
        var pubkey1 = (n >= 1) ? redemption_script.chunks[1] : null;
        var pubkey2 = (n >= 2) ? redemption_script.chunks[2] : null;
        var pubkey3 = (n >= 3) ? redemption_script.chunks[3] : null;
        var pubkeys = [pubkey1, pubkey2, pubkey3];

        for( var j = 0; j < pubkeys.length; j++ ) {
            if( pubkeys[j] === null ) continue;

            for( var k = 0; k < eckeyarr.length; k++ ) {
                if( eckeyarr[k] === null ) continue;
                else if( pubkey_matches_privkey(pubkeys[j], eckeyarr[k]) ) {
                    eckeys.push(eckeyarr[k]);
                    break;
                }
            }

            if( eckeys.length == m ) break;
        }


        if( eckeyarr[0] !== null && !array_has_object(eckeys, eckeyarr[0]) ) setErrorState($('#txSec1'), true, 'Key is not valid for redemption script');
        if( eckeyarr[1] !== null && !array_has_object(eckeys, eckeyarr[1]) ) setErrorState($('#txSec2'), true, 'Key is not valid for redemption script');
        if( eckeyarr[2] !== null && !array_has_object(eckeys, eckeyarr[2]) ) setErrorState($('#txSec3'), true, 'Key is not valid for redemption script');

        var addr = $('#txAddr').val();
        var unspent = $('#txUnspent').val();
        var balance = parseFloat($('#txBalance').val());
        var fee = parseFloat('0'+$('#txFee').val());

        TX.init(eckeys, redemption_script);

        var fval = 0;
        var o = txGetOutputs();
        for (i in o) {
            TX.addOutput(o[i].dest, o[i].fval);
            fval += o[i].fval;
        }

        // send change back or it will be sent as fee
        // Current BitcoinJS won't let us return the change to ourselves.
        // It throwns an exception in Bitcoin.Address.decodeString complaining about "Version 5" addresses.
        // if (balance > fval + fee) {
        //     var change = balance - fval - fee;
        //     TX.addOutput(addr, change);
        // }

        try {
            var sendTx = TX.construct();
            var txJSON = TX.toBBE(sendTx);
            var buf = sendTx.serialize();
            var txHex = Crypto.util.bytesToHex(buf);
            setErrorState($('#txJSON'), false, '');
            $('#txJSON').val(txJSON);
            $('#txHex').val(txHex);
        } catch(err) {
            if( ('' + err) == 'Version 5 not supported!' ) {
                alert("The current version of BitcoinJS does not support spending to P2SH addresses yet.")
            }
            $('#txJSON').val('');
            $('#txHex').val('');
        }
    }

    function txRebuildFromRawTransaction() {
        $("#txJSON").val('');
        $("#txHex").val('');

        if(raw_transaction === null) {
            return;
        }

        var tx = raw_transaction.clone();
        var inputs = JSON.parse($("#txUnspent").val())["unspent_outputs"];

        var bytes = Crypto.util.hexToBytes($('#txRedemptionScript').val());
        var redemption_script = new Bitcoin.Script(bytes);

        var m = redemption_script.buffer[0] - Bitcoin.Opcode.map["OP_1"] + 1;
        var n = redemption_script.buffer[redemption_script.buffer.length-2] - Bitcoin.Opcode.map["OP_1"] + 1;
        var left = m - inputs[0].signatures.length;

        var eckeyarr = [txKey(1), 
                        (left > 1) ? txKey(2) : null, 
                        (left > 2) ? txKey(3) : null];

        // Need to determine the order of the keys in the redemption script.
        // And build 'eckeys' in an order that matches
        var pubkey1 = (n >= 1) ? redemption_script.chunks[1] : null;
        var pubkey2 = (n >= 2) ? redemption_script.chunks[2] : null;
        var pubkey3 = (n >= 3) ? redemption_script.chunks[3] : null;
        var pubkeys = [pubkey1, pubkey2, pubkey3];

        // Convert byte arrays to pubkeys
        for(var i = 0; i < pubkeys.length; i++) {
            if(pubkeys[i] == null) continue;
            var pk = new Bitcoin.ECKey();
            pk.compressed = true;
            pk.pub = decompress_pubkey(pubkeys[i]);
            pk.pubKeyHash = Bitcoin.Util.sha256ripe160(pk.getPub());
            pubkeys[i] = pk;
        }

        var complete = true;
        var used_sec = [false, false, false];

        // for each input, build a new scriptSig
        for(var i = 0; i < tx.ins.length; i++) {
            var tx_in = tx.ins[i];
            var input = inputs[i];

            var hash_for_signature = tx.hashTransactionForSignature(redemption_script, i, SIGHASH_ALL);

            // get the keys and try to sign tx. signkeys is an array of both
            // private keys and signatures, the order matching the order
            // of public keys
            var signkeys = new Array();
            for(var j = 0; j < pubkeys.length; j++) {
                if(pubkeys[j] == null) continue;

                // do any signatures match?
                var sig = null;
                for(var k = 0; k < input.signatures.length; k++) {
                    var signature = Crypto.util.hexToBytes(input.signatures[k]);

                    if(verify_signature(signature, hash_for_signature, pubkeys[j].getPubPoint())) {
                        sig = signature;
                        break;
                    }
                }

                // do any private keys match?
                var eckey = null;
                for(var k = 0; k < eckeyarr.length; k++) {
                    if(eckeyarr[k] !== null && pubkey_matches_privkey(pubkeys[j].getPub(), eckeyarr[k])) {
                        eckey = eckeyarr[k];
                        used_sec[k] = true;

                        // if both are found, error
                        if(sig !== null) {
                            setErrorState($("#txSec" + (k+1)), true, 'Duplicating signature from key');
                            return;
                        }
                        break;
                    }
                }

                if(sig === null && eckey === null) {
                    setErrorState($("#txSec" + (k+1)), true, 'Not a useful key');
                    continue;
                }

                // otherwise take the one that matches and stick it in signkeys
                if(sig !== null) {
                    signkeys.push(sig);
                } else {
                    signkeys.push(eckey);
                }
            }

            // build scriptSig, 0x00 <signature> .. <signature> <redemption script>
            var script = new Bitcoin.Script();
            script.writeOp(0);
            for(var j = 0; j < signkeys.length; j++) {
                var sig;
                if(signkeys[j] instanceof Bitcoin.ECKey) {
                    sig = signkeys[j].sign(hash_for_signature);
                } else {
                    sig = signkeys[j].slice(0);
                }
                sig.push(parseInt(SIGHASH_ALL, 10));
                script.writeBytes(sig);
            }

            script.writeBytes(redemption_script.buffer);
            tx_in.script = script;

            if(signkeys.length < m) complete = false;
        }

        for(var i = 0; i < used_sec.length; i++) {
            if(eckeyarr[i] !== null && !used_sec[i]) {
                setErrorState($("#txSec" + (i+1)), true, 'Key is not useful for this transaction');
            }
        }

        try {
            $("#txJSON").val(TX.toBBE(tx));
            $("#txHex").val(Crypto.util.bytesToHex(tx.serialize()));
            setErrorState($("#txJSON"), false, '');
        } catch(err) {
            $('#txJSON').val('');
            $('#txHex').val('');
        }
    }

    function txSign() {
        if (txFrom=='txFromSec')
        {
            txRebuild();
            return;
        }

        var str = $('#txJSON').val();
        TX.removeOutputs();
        var sendTx = TX.fromBBE(str);

        try {
            sendTx = TX.resign(sendTx);
            $('#txJSON').val(TX.toBBE(sendTx));
            $('#txHex').val(Crypto.util.bytesToHex(sendTx.serialize()));
            $('#txFee').val(Bitcoin.Util.formatValue(TX.getFee(sendTx)));
        } catch(err) {
            $('#txJSON').val('');
            $('#txHex').val('');
        }
    }

    function txOnChangeDest() {
        var balance = parseFloat($('#txBalance').val());
        var fval = parseFloat('0'+$('#txValue').val());
        var fee = parseFloat('0'+$('#txFee').val());

        if (fval + fee > balance) {
            fee = balance - fval;
            $('#txFee').val(fee > 0 ? fee : '0.00');
        }

        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
    }

    function txShowUnspent() {
        var div = $('#txUnspentForm');

        if (div.hasClass('hide')) {
            div.removeClass('hide');
            $('#txShowUnspent').text('Hide Outputs');
        } else {
            div.addClass('hide');
            $('#txShowUnspent').text('Show Outputs');
        }
    }

    function txChangeType() {
        txType = $(this).attr('id');
    }

    function txOnChangeFee() {

        var balance = parseFloat($('#txBalance').val());
        var fee = parseFloat('0'+$('#txFee').val());

        var fval = 0;
        var o = txGetOutputs();
        for (i in o) {
            TX.addOutput(o[i].dest, o[i].fval);
            fval += o[i].fval;
        }

        if (fval + fee > balance) {
            fval = balance - fee;
            $('#txValue').val(fval < 0 ? 0 : fval);
        }

        if (fee == 0 && fval == balance - 0.0005) {
            $('#txValue').val(balance);
        }

        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
    }

    function txGetOutputs() {
        var res = [];
        $.each($(document).find('.txCC'), function() {
            var dest = $(this).find('#txDest').val();
            var fval = parseFloat('0' + $(this).find('#txValue').val());
            res.push( {"dest":dest, "fval":fval } );
        });
        return res;
    }

    function translate_txDest() {
        $.each($(document).find('.txCC'), function() {
            var dest = $(this).find('#txDest');

            var decoded = Bitcoin.Base58.decode(dest.val());
            var checksum = Crypto.SHA256(Crypto.SHA256(decoded.slice(0, decoded.length-4), {asBytes: true}), {asBytes: true});

            if( Crypto.util.bytesToHex(checksum.slice(0, 4)) != Crypto.util.bytesToHex(decoded.slice(decoded.length-4)) ) {
                return;
            }

            if( decoded[0] == 0 && coin == 'btc_test' ) {
                decoded = [111].concat(decoded.slice(1, decoded.length-4));
            } else if( decoded[0] == 111 && coin == 'btc_main' ) {
                decoded = [0].concat(decoded.slice(1, decoded.length-4));
            } else {
                return;
            }

            checksum = Crypto.SHA256(Crypto.SHA256(decoded, {asBytes: true}), {asBytes: true});
            dest.val(Bitcoin.Base58.encode(decoded.concat(checksum.slice(0, 4))));
        });

        txRebuild();
    }

    function crChange(e)
    {
        e.preventDefault();
        coin = $(this).attr("id");
        ADDRESS_URL_PREFIX = $(this).attr('href');
        $('#crName').text($(this).text());
        $('#crSelect').dropdown('toggle');
        txOnChangeRedemptionScript();
        update_p2sh_address();
        translate_txDest();
        translate_extended_public_keys();
        translate();
        return false;
    }

    $(document).ready( function() {

        if (window.location.hash)
          $('#tab-' + window.location.hash.substr(1).split('?')[0]).tab('show');

        $('a[data-toggle="tab"]').on('click', function (e) {
            window.location.hash = $(this).attr('href');
        });

        // bip32

        $('#key_derivation label input').on('change', update_key_derivation );
        $('#extpubkeys_from label input').on('change', update_extpubkeys_from );

        updateExtpubkeysFrom();
        extpubkeysFromUpdateLabel();
        updateKeyDerivation();
        keyDerivationUpdateLabel();

        $("#extpub1").val("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
        $("#extpub2").val("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
        $("#extpub3").val("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
        $("#bip32private_key1").val("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
        $("#bip32private_key2").val("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");
        $("#bip32private_key3").val("xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j");

        onInput('#extpub1', onChangeExtendedPublicKey);
        onInput('#extpub2', onChangeExtendedPublicKey);
        onInput('#extpub3', onChangeExtendedPublicKey);
        onInput('#extpublic_key_package', onChangeExtendedPublicKeyPackage);
        onChangeExtendedPublicKey();
        
        onInput("#bip32private_key1", onChangeExtendedPrivateKey);
        onInput("#bip32private_key2", onChangeExtendedPrivateKey);
        onInput("#bip32private_key3", onChangeExtendedPrivateKey);
        onInput("#chain_index", onChangeChainIndex);

        $("#bip32CreateP2SH").click(function() { return bip32CreateP2SH(false); });
        $("#bip32SpendP2SH").click(bip32SpendP2SH);

        // generator

        onInput('#pub1', onChangePublicKey);
        onInput('#pub2', onChangePublicKey);
        onInput('#pub3', onChangePublicKey);
        onInput('#redemption_script', onChangeRedemptionScript);

        $('#pubkeys_from label input').on('change', update_pubkeys_from );
        $('#req_count label input').on('change', update_req_count );
        $('#outof_count label input').on('change', update_outof_count );

        $("#pubkey_order_prev").on('click', pubkey_order_prev );
        $("#pubkey_order_next").on('click', pubkey_order_next );

        initializePublicKeys();
        reqUpdateLabel();
        outofUpdateLabel();

        // transactions

        $("#spend_from label input").on('change', update_spend_from );
        spendFromUpdateLabel();

        $("#txRedemptionScript").val('522103d728ad6757d4784effea04d47baafa216cf474866c2d4dc99b1e8e3eb936e7302102d83bba35a8022c247b645eed6f81ac41b7c1580de550e7e82c75ad63ee9ac2fd2103aeb681df5ac19e449a872b9e9347f1db5a0394d2ec5caf2a9c143f86e232b0d953ae');
        $("#txRawTransaction").val('');
        txOnChangeRedemptionScript();
        //txOnChangeRawTransaction();

        $("#txRawTransactionDiv").addClass("hide");

        $("#txSec1").val('KybuecAGpGhfLP4y6bd6bidFn23dGK2EJJi8zvbwjoffYd14EsU6');
        $("#txSec2").val('L11z9LhtCJmPPtK4cwMC4s9s9R3uXkuPkmGfjBmUGGHn7eFejiPC');
        $("#txSec3").val('L1idoWSvtirHZgYU5eVFGHSHG9xXB72AyLSupfQrs6JUvUAPSKzS');

        $('#txDest').val(tx_dest);

        txSetUnspent(JSON.parse(tx_unspent));

        $('#txGetUnspent').click(txGetUnspent);
        $('#txType label input').on('change', txChangeType);

        onInput($('#txSec1'), txOnChangeSec);
        onInput($('#txSec2'), txOnChangeSec);
        onInput($('#txSec3'), txOnChangeSec);
        onInput($('#txRedemptionScript'), txOnChangeRedemptionScriptDelayed);
        onInput($('#txRawTransaction'), txOnChangeRawTransactionDelayed);
        onInput($('#txUnspent'), txOnChangeUnspent);
        onInput($('#txHex'), txOnChangeHex);
        onInput($('#txJSON'), txOnChangeJSON);
        onInput($('#txDest'), txOnChangeDest);
        onInput($('#txValue'), txOnChangeDest);
        onInput($('#txFee'), txOnChangeFee);

        $('#txAddDest').click(txOnAddDest);
        $('#txRemoveDest').click(txOnRemoveDest);
        $('#txSign').click(txSign);

        // converter

        onInput('#src', onChangeFrom);

        $('#enc_from label input').on('change', update_enc_from );
        $('#enc_to label input').on('change', update_enc_to );

        // currency select

        $('#crCurrency ul li a').on('click', crChange);

    });
})(jQuery);
