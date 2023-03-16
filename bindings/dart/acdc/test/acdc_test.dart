import 'dart:ffi';

import 'package:acdc/acdc.dart';
import 'package:test/test.dart';

void main() {
 test('it works', () async {
    final dylib = DynamicLibrary.open("../target/debug/libacdcdart.so");

    late final api = DartImpl(dylib);

    var acdc = await ACDC.newACDC(bridge: api, issuer: "Issuer", schema: "EFNWOR0fQbv_J6EL0pJlvCxEpbu4bg1AurHgr_0A7LKc", data: """{"hello":"world"}""");
    var encoded = await acdc.encode();
    expect(encoded, """{"v":"ACDC10JSON0000aa_","d":"EHaPRLWlw9RkQxgn9BGWzgJwsQy0HtOksqAstXbxo_NB","i":"Issuer","ri":"","s":"EFNWOR0fQbv_J6EL0pJlvCxEpbu4bg1AurHgr_0A7LKc","a":{"hello":"world"}}""");
    var loaded = await ACDC.parse(bridge: api, stream: encoded);

    expect(await loaded.getIssuer(), "Issuer");
    expect(await loaded.getData(), """{"hello":"world"}""");
    expect(await loaded.getSchema(), "EFNWOR0fQbv_J6EL0pJlvCxEpbu4bg1AurHgr_0A7LKc");

  }); 
}
