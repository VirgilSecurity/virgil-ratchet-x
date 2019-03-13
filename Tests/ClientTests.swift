//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import XCTest
import VirgilSDK
import VirgilCrypto
import VirgilCryptoRatchet
import VirgilCryptoFoundation
@testable import VirgilSDKRatchet

class ClientTests: XCTestCase {
    let keyUtils = RatchetKeyUtils()
    
    private func initialize() -> (JwtGenerator, String, VirgilPrivateKey, Card, RatchetClient) {
        let testConfig = TestConfig.readFromBundle()
        
        let client = RatchetClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let crypto = try! VirgilCrypto()
        let identityKeyPair = try! crypto.generateKeyPair(ofType: .ed25519)
        
        let identity = NSUUID().uuidString
        
        let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
        
        let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(virgilCrypto: crypto), appId: testConfig.AppId, ttl: 10050)
        
        let tokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            completion(try! generator.generateToken(identity: identity), nil)
        })
        
        let cardVerifier = VirgilCardVerifier(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto))!
        cardVerifier.verifyVirgilSignature = false
        
        let cardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(virgilCrypto: crypto), accessTokenProvider: tokenProvider, cardVerifier: cardVerifier)
        cardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let cardManager = CardManager(params: cardManagerParams)
        
        let card = try! cardManager.publishCard(privateKey: identityKeyPair.privateKey, publicKey: identityKeyPair.publicKey).startSync().getResult()
        
        return (generator, identity, identityKeyPair.privateKey, card, client)
    }
    
    func test1__full_cycle__long_term_key__should_succeed() {
        let (generator, identity, privateKey, card, client) = self.initialize()
        
        let crypto = try! VirgilCrypto()
        
        let longTermKey = try! crypto.generateKeyPair(ofType: .curve25519)
        
        let longTermPublicKey = try! crypto.exportPublicKey(longTermKey.publicKey)
        let longTermKeyId = try! self.keyUtils.computePublicKeyId(publicKey: longTermPublicKey)
        let signature = try! crypto.generateSignature(of: longTermPublicKey, using: privateKey)
        
        let signedLongTermKey = SignedPublicKey(publicKey: longTermPublicKey, signature: signature)
        
        let token = try! generator.generateToken(identity: identity).stringRepresentation()
        
        try! client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [], token: token)
        
        let response1 = try! client.validatePublicKeys(longTermKeyId: longTermKeyId, oneTimeKeysIds: [], token: token)
        
        XCTAssert(response1.usedLongTermKeyId == nil)
        
        let response2 = try! client.getPublicKeySet(forRecipientIdentity: identity, token: token)
        
        XCTAssert(response2.longTermPublicKey.publicKey == signedLongTermKey.publicKey)
        XCTAssert(response2.longTermPublicKey.signature == signedLongTermKey.signature)
        XCTAssert(response2.oneTimePublicKey == nil)
    }
    
    func test2__full_cycle__all_keys__should_succeed() {
        let (generator, identity, privateKey, card, client) = self.initialize()
        
        let crypto = try! VirgilCrypto()
        
        let longTermKey = try! crypto.generateKeyPair(ofType: .curve25519)
        let oneTimeKey1 = try! crypto.exportPublicKey(try! crypto.generateKeyPair(ofType: .curve25519).publicKey)
        let oneTimeKey2 = try! crypto.exportPublicKey(try! crypto.generateKeyPair(ofType: .curve25519).publicKey)
        
        let oneTimeKeyId1 = try! self.keyUtils.computePublicKeyId(publicKey: oneTimeKey1)
        let oneTimeKeyId2 = try! self.keyUtils.computePublicKeyId(publicKey: oneTimeKey2)
        
        let longTermPublicKey = try! crypto.exportPublicKey(longTermKey.publicKey)
        let longTermKeyId = try! self.keyUtils.computePublicKeyId(publicKey: longTermPublicKey)
        let signature = try! crypto.generateSignature(of: longTermPublicKey, using: privateKey)
        
        let signedLongTermKey = SignedPublicKey(publicKey: longTermPublicKey, signature: signature)
        
        let token = try! generator.generateToken(identity: identity).stringRepresentation()
        
        try! client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [oneTimeKey1, oneTimeKey2], token: token)
        
        let response1 = try! client.validatePublicKeys(longTermKeyId: longTermKeyId, oneTimeKeysIds: [oneTimeKeyId1, oneTimeKeyId2], token: token)
        
        XCTAssert(response1.usedLongTermKeyId == nil)
        XCTAssert(response1.usedOneTimeKeysIds.isEmpty)
        
        let response2 = try! client.getPublicKeySet(forRecipientIdentity: identity, token: token)
        
        XCTAssert(response2.longTermPublicKey.publicKey == signedLongTermKey.publicKey)
        XCTAssert(response2.longTermPublicKey.signature == signedLongTermKey.signature)
        
        let usedKeyId: Data
        if (response2.oneTimePublicKey == oneTimeKey1) {
            usedKeyId = oneTimeKeyId1
        }
        else if (response2.oneTimePublicKey == oneTimeKey2) {
            usedKeyId = oneTimeKeyId2
        }
        else {
            usedKeyId = Data()
            XCTFail()
        }
        
        let response3 = try! client.validatePublicKeys(longTermKeyId: longTermKeyId, oneTimeKeysIds: [oneTimeKeyId1, oneTimeKeyId2], token: token)
        
        XCTAssert(response3.usedLongTermKeyId == nil)
        XCTAssert(response3.usedOneTimeKeysIds.count == 1)
        XCTAssert(response3.usedOneTimeKeysIds[0] == usedKeyId)
    }
    
    func test3__reset__all_keys__should_succeed() {
        let (generator, identity, privateKey, card, client) = self.initialize()
        
        let crypto = try! VirgilCrypto()
        
        let longTermKey = try! crypto.generateKeyPair(ofType: .curve25519)
        let oneTimeKey = try! crypto.exportPublicKey(try! crypto.generateKeyPair(ofType: .curve25519).publicKey)
        
        let longTermPublicKey = try! crypto.exportPublicKey(longTermKey.publicKey)
        let signature = try! crypto.generateSignature(of: longTermPublicKey, using: privateKey)
        
        let signedLongTermKey = SignedPublicKey(publicKey: longTermPublicKey, signature: signature)
        
        let token = try! generator.generateToken(identity: identity).stringRepresentation()
        
        try! client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [oneTimeKey], token: token)
        
        try! client.deleteKeysEntity(token: token)
        
        do {
            _ = try client.getPublicKeySet(forRecipientIdentity: identity, token: token)
            XCTFail()
        }
        catch { }
        
        try! client.uploadPublicKeys(identityCardId: card.identifier, longTermPublicKey: signedLongTermKey, oneTimePublicKeys: [oneTimeKey], token: token)
        
        let response = try! client.getPublicKeySet(forRecipientIdentity: identity, token: token)
        
        XCTAssert(response.longTermPublicKey.publicKey == signedLongTermKey.publicKey)
        XCTAssert(response.longTermPublicKey.signature == signedLongTermKey.signature)
        XCTAssert (response.oneTimePublicKey == oneTimeKey)
    }
}
